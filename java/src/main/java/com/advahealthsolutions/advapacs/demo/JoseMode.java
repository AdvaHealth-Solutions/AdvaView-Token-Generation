package com.advahealthsolutions.advapacs.demo;

/** How the token payload is protected. The default is {@link #JWE}. */
public enum JoseMode {
  /** No protection: prints the raw JSON payload. For debugging only - never send this to AdvaView. */
  JSON,

  /**
   * JSON Web Signature (RFC 7515). The payload is signed with HMAC-SHA256 so it cannot be altered,
   * but it is only base64url-encoded, so anyone who sees the token can read it. Use only if you
   * can't use {@link #JWE}.
   */
  JWS,

  /**
   * JSON Web Encryption (RFC 7516). <b>Recommended.</b> The payload is encrypted with AES-256-GCM,
   * so it can neither be read nor altered without the access key. Patient identifiers (PHI) in the
   * payload can't leak into server logs, proxies or browser history.
   */
  JWE;

  public static JoseMode fromString(String value) {
    return switch (value.toLowerCase()) {
      case "jwe" -> JWE;
      case "jws" -> JWS;
      case "json" -> JSON;
      default -> throw new IllegalArgumentException("--mode must be jwe, jws or json");
    };
  }
}
