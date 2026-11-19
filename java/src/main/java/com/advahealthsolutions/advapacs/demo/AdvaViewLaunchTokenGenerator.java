package com.advahealthsolutions.advapacs.demo;

/**
 * Example: generating an AdvaView launch token.
 *
 * <p>An AdvaView launch token is a short-lived credential that grants a named user access to a
 * specific set of studies in AdvaView, the AdvaPACS viewer. Your system builds the token, protects
 * it with the access key you were issued, and passes it to AdvaView.
 *
 * <h2>How a launch token is produced</h2>
 *
 * <ol>
 *   <li><b>Collect the inputs</b> ({@link ArgParser}, {@link Config}) - who the user is, which
 *       studies they may open, and how long the token should live.
 *   <li><b>Build the JSON payload</b> ({@link PayloadBuilder}) - the claims AdvaView will read.
 *   <li><b>Protect the payload</b> ({@link JoseService}) - encrypt it (JWE, recommended) or sign
 *       it (JWS) using your access key. Encrypting keeps patient identifiers (PHI) out of server
 *       logs, proxies and browser history.
 * </ol>
 *
 * <h2>Example payload</h2>
 *
 * Studies are identified either by Study Instance UID:
 *
 * <pre>
 * {
 *   "username":  "jane.doe@example.com",
 *   "studies":   [ { "studyInstanceUid": "1.2.840.113619.2.55.3.1234" } ],
 *   "expiresAt": 1763500000,
 *   "jti":       "3f6c1d2e-8a4b-4c1e-9f2a-7b5d6e8c9a01"
 * }
 * </pre>
 *
 * or by patient ID plus one or more accession numbers:
 *
 * <pre>
 * {
 *   "username":  "jane.doe@example.com",
 *   "patientId": "PAT12345",
 *   "studies":   [ { "accessionNumber": "ACC0001" }, { "accessionNumber": "ACC0002" } ],
 *   "expiresAt": 1763500000,
 *   "jti":       "3f6c1d2e-8a4b-4c1e-9f2a-7b5d6e8c9a01"
 * }
 * </pre>
 *
 * <h2>Running the example</h2>
 *
 * <pre>
 *   mvn package
 *   java -jar target/advaview-launch-token-generator-1.0-SNAPSHOT.jar \
 *       --username jane.doe@example.com \
 *       --suid 1.2.840.113619.2.55.3.1234 \
 *       --accessKeyId &lt;your access key id&gt; \
 *       --accessKeySecret &lt;your access key secret&gt; \
 *       --expireAfter 300
 * </pre>
 *
 * <p>Tokens are encrypted (JWE) by default. Use {@code --mode json} to print the unprotected
 * payload, which is handy for checking what will go into the token. Only a JWE (or JWS) token
 * should ever be sent to AdvaView.
 */
public class AdvaViewLaunchTokenGenerator {

  public static void main(String[] args) {
    try {
      // Step 1: read and validate the command-line inputs.
      Config config = new ArgParser().parse(args);

      // Step 2: build the JSON payload (the token's claims).
      String jsonPayload = new PayloadBuilder().buildJson(config);

      JoseMode mode = config.getMode();
      if (mode == JoseMode.JSON) {
        // Debug output only: this payload is NOT protected and must not be used as a token.
        System.out.println(jsonPayload);
        return;
      }

      // Signing and encryption both need the access key issued to you by AdvaPACS.
      if (config.getAccessKeyId() == null || config.getAccessKeyId().isEmpty()) {
        throw new IllegalArgumentException("accessKeyId is required when mode is " + mode);
      }
      if (config.getAccessKeySecret() == null || config.getAccessKeySecret().isEmpty()) {
        throw new IllegalArgumentException("accessKeySecret is required when mode is " + mode);
      }

      // Step 3: protect the payload with the access key.
      JoseService joseService =
          new JoseService(config.getAccessKeyId(), config.getAccessKeySecret());

      String token =
          switch (mode) {
            case JWE -> joseService.encrypt(jsonPayload); // recommended: contents hidden + tamper-proof
            case JWS -> joseService.sign(jsonPayload); // tamper-proof, but readable by anyone
            default -> throw new IllegalStateException("Unsupported mode: " + mode);
          };

      System.out.println(token);
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      printUsage();
      System.exit(1);
    }
  }

  private static void printUsage() {
    System.err.println();
    System.err.println("Usage:");
    System.err.println("  java -jar advaview-launch-token-generator.jar \\");
    System.err.println("    --username <username> \\");
    System.err.println("    --expireAfter <seconds> \\");
    System.err.println("    [--suid <suid> ...]                # OR the two options below");
    System.err.println("    [--patientId <patientId>] \\");
    System.err.println("    [--accNum <accNum> ...] \\");
    System.err.println("    --accessKeyId <id> \\                # required unless --mode json");
    System.err.println("    --accessKeySecret <secret> \\        # required unless --mode json");
    System.err.println("    [--mode jwe|jws|json]              # default: jwe");
  }
}
