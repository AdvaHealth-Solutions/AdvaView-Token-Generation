# Go example

Generates an AdvaView launch token using [go-jose](https://github.com/go-jose/go-jose).
See the [top-level README](../README.md) for the token format.

## Requirements

- Go 1.24+

## Run

```
go run . \
    --username jane.doe@example.com \
    --suid 1.2.840.113619.2.55.3.1234 \
    --accessKeyId <your key id> \
    --accessKeySecret <your key secret> \
    --expireAfter 300
```

## Where to look

Everything is in [`main.go`](main.go), laid out as three steps:
`readInputs()` → `buildPayload()` → `sign()` / `encrypt()`.
