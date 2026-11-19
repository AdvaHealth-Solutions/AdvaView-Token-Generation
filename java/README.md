# Java example

Generates an AdvaView launch token using [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).
See the [top-level README](../README.md) for the token format.

## Requirements

- Java 17+
- Maven 3.8+

## Run

```
mvn package
java -jar target/advaview-launch-token-generator-1.0-SNAPSHOT.jar \
    --username jane.doe@example.com \
    --suid 1.2.840.113619.2.55.3.1234 \
    --accessKeyId <your key id> \
    --accessKeySecret <your key secret> \
    --expireAfter 300
```

## Where to look

All code is in `src/main/java/com/advahealthsolutions/advapacs/demo/`:

| File                                | Purpose                                                 |
|-------------------------------------|---------------------------------------------------------|
| `AdvaViewLaunchTokenGenerator.java` | Entry point; walks through the three steps.             |
| `PayloadBuilder.java`               | Builds the JSON payload (the token's claims).           |
| `JoseService.java`                  | Key derivation, encryption (JWE) and signing (JWS).     |
| `Config.java`                       | The inputs and their validation rules.                  |
| `ArgParser.java`                    | Command-line parsing (example plumbing only).           |
| `JoseMode.java`                     | The output modes: `jwe` (default), `jws`, `json`.       |
