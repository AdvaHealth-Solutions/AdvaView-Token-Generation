# AdvaView Launch Token Examples

Example code showing how to generate **AdvaView launch tokens** in several languages.

An AdvaView launch token is a short-lived credential that lets a named user open a specific set of
studies in AdvaView, the AdvaPACS viewer. Your system builds the token on the server, protects it with
the access key AdvaPACS issued you, and passes it to AdvaView.

> These are reference examples, not production libraries. Adapt them to your own
> application, and keep your access key secret on the server. Never send it to a browser.

## Examples

| Language | Folder                 | JOSE library                                                   |
|----------|------------------------|----------------------------------------------------------------|
| Java     | [`java/`](java/)       | [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) |
| Node.js  | [`nodejs/`](nodejs/)   | [jose](https://github.com/panva/jose)                          |
| Go       | [`go/`](go/)           | [go-jose](https://github.com/go-jose/go-jose)                  |
| Python   | [`python/`](python/)   | [jwcrypto](https://github.com/latchset/jwcrypto)               |
| .NET     | [`dotnet/`](dotnet/)   | [jose-jwt](https://github.com/dvsekhvalnov/jose-jwt)           |

Each folder has its own README with setup and run instructions. All five produce
identical tokens, so pick whichever matches your stack.

## How a launch token is produced

1. **Collect the inputs**: who the user is, which studies they may open, and how long the
   token should live.
2. **Build the JSON payload**: the claims AdvaView will read.
3. **Protect the payload**: encrypt it (JWE, recommended) or sign it (JWS) with your access key.

## Token format

### Payload

Identify studies **either** by Study Instance UID:

```json
{
  "username":  "jane.doe@example.com",
  "studies":   [ { "studyInstanceUid": "1.2.840.113619.2.55.3.1234" } ],
  "expiresAt": 1763500000,
  "jti":       "3f6c1d2e-8a4b-4c1e-9f2a-7b5d6e8c9a01"
}
```

**or** by patient ID plus one or more accession numbers:

```json
{
  "username":  "jane.doe@example.com",
  "patientId": "PAT12345",
  "studies":   [ { "accessionNumber": "ACC0001" }, { "accessionNumber": "ACC0002" } ],
  "expiresAt": 1763500000,
  "jti":       "3f6c1d2e-8a4b-4c1e-9f2a-7b5d6e8c9a01"
}
```

| Field       | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `username`  | The user the token is issued to.                                            |
| `patientId` | Only present when studies are identified by accession number.               |
| `studies`   | Each entry has a `studyInstanceUid` **or** an `accessionNumber`.            |
| `expiresAt` | Expiry time in seconds since the Unix epoch (UTC). Keep tokens short-lived. |
| `jti`       | A new random unique ID for every token (e.g. a UUID). AdvaPACS uses it to reject a token presented more than once. |

### Protecting the payload

**Use JWE (encrypted) tokens.** The payload contains patient identifiers (PHI), and launch
tokens travel in URLs, so they end up in places you don't control: server and proxy logs,
browser history, and analytics tools. A JWS token is only signed: its payload is base64url-encoded
and anyone who sees the token can decode it. A JWE token is encrypted, so nothing in it can be
read without your access key.

| Setting                   | Value                                                                    |
|---------------------------|--------------------------------------------------------------------------|
| Key                       | `SHA-256(UTF-8 bytes of your access key secret)`: 32 bytes. Use the hash, not the raw secret. |
| `kid` header              | Your access key ID                                                       |
| **JWE (recommended)**     | `alg: A256KW`, `enc: A256GCM`. Encrypted and tamper-proof.               |
| JWS                       | `alg: HS256`. Tamper-proof, but the payload is readable. Use only if you can't use JWE. |
| Serialization             | Compact: five-part JWE, or three-part JWS (`header.payload.signature`)   |

Any standards-compliant JOSE/JWT library can produce these tokens if it follows these rules.

## Common options

All examples accept the same command-line options:

```
--username <username>            required
--expireAfter <seconds>          required; token lifetime from now
--suid <uid>                     repeatable; OR use --patientId with --accNum
--patientId <id>
--accNum <accession>             repeatable
--accessKeyId <id>               required unless --mode json
--accessKeySecret <secret>       required unless --mode json
--mode jwe|jws|json              default jwe (recommended); json prints the unprotected
                                 payload, for debugging only
```

Example:

```
--username jane.doe@example.com --suid 1.2.840.113619.2.55.3.1234 \
--accessKeyId <your key id> --accessKeySecret <your key secret> --expireAfter 300
```

In your own integration, these values would come from your application (the signed-in user,
the studies being viewed) and your secrets manager (the access key), not the command line.
