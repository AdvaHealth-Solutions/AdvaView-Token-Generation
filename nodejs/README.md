# Node.js example

Generates an AdvaView launch token using [jose](https://github.com/panva/jose).
See the [top-level README](../README.md) for the token format.

## Requirements

- Node.js 20+

## Run

```
npm install
node generate-token.mjs \
    --username jane.doe@example.com \
    --suid 1.2.840.113619.2.55.3.1234 \
    --accessKeyId <your key id> \
    --accessKeySecret <your key secret> \
    --expireAfter 300
```

## Where to look

Everything is in [`generate-token.mjs`](generate-token.mjs), laid out as three steps:
`readInputs()` → `buildPayload()` → `sign()` / `encrypt()`.
