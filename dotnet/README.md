# .NET example

Generates an AdvaView launch token in C# using [jose-jwt](https://github.com/dvsekhvalnov/jose-jwt).
See the [top-level README](../README.md) for the token format.

## Requirements

- .NET 8 SDK or later

## Run

```
dotnet run -- \
    --username jane.doe@example.com \
    --suid 1.2.840.113619.2.55.3.1234 \
    --accessKeyId <your key id> \
    --accessKeySecret <your key secret> \
    --expireAfter 300
```

## Where to look

Everything is in [`Program.cs`](Program.cs), laid out as three steps:
`Inputs.Parse()` → `TokenPayload.Build()` → `TokenProtector.Sign()` / `TokenProtector.Encrypt()`.
