package com.advahealthsolutions.advapacs.demo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.MACSigner;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Signs or encrypts a token payload using your AdvaPACS access key.
 *
 * <p>This example uses the <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus
 * JOSE+JWT</a> library, but any standards-compliant JOSE library will work, provided it follows the
 * same rules:
 *
 * <ul>
 *   <li><b>Key derivation:</b> the 256-bit key is the SHA-256 hash of the UTF-8 bytes of the access
 *       key secret. Use the hash, not the raw secret.
 *   <li><b>Key ID:</b> the access key ID is placed in the {@code kid} header so AdvaPACS knows
 *       which key to use when checking the token.
 *   <li><b>JWE (recommended):</b> key management {@code A256KW}, content encryption {@code
 *       A256GCM}. The payload is encrypted, so patient identifiers (PHI) can't leak into server
 *       logs, proxies or browser history.
 *   <li><b>JWS:</b> algorithm {@code HS256}. Tamper-proof, but anyone who sees the token can read
 *       the payload. Use only if you can't use JWE.
 * </ul>
 *
 * <p>All tokens use compact serialization ({@code xxxxx.yyyyy.zzzzz}).
 */
public class JoseService {

  private final byte[] keyBytes;
  private final String accessKeyId;

  public JoseService(String accessKeyId, String accessKeySecret) {
    if (accessKeySecret == null || accessKeySecret.isEmpty()) {
      throw new IllegalArgumentException("accessKeySecret must not be null or empty");
    }
    this.keyBytes = deriveKey(accessKeySecret);
    this.accessKeyId = accessKeyId;
  }

  /** Derives the 256-bit key: SHA-256(UTF-8 bytes of the access key secret). */
  private static byte[] deriveKey(String accessKeySecret) {
    try {
      return MessageDigest.getInstance("SHA-256")
          .digest(accessKeySecret.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Returns a compact JWS: the payload signed with HMAC-SHA256.
   *
   * <p>Header: {@code {"alg":"HS256","kid":"<accessKeyId>"}}
   */
  public String sign(String jsonPayload) {
    try {
      JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(accessKeyId).build();

      JWSObject jwsObject = new JWSObject(header, new Payload(jsonPayload));
      jwsObject.sign(new MACSigner(keyBytes));

      return jwsObject.serialize();
    } catch (JOSEException e) {
      throw new RuntimeException("Failed to sign payload as JWS", e);
    }
  }

  /**
   * Returns a compact JWE: the payload encrypted with AES-256-GCM.
   *
   * <p>Header: {@code {"alg":"A256KW","enc":"A256GCM","kid":"<accessKeyId>"}}
   *
   * <p>A fresh random content key is generated for every token and wrapped (AES Key Wrap) with the
   * derived key; the library handles this for you.
   */
  public String encrypt(String jsonPayload) {
    try {
      JWEHeader header =
          new JWEHeader.Builder(JWEAlgorithm.A256KW, EncryptionMethod.A256GCM)
              .keyID(accessKeyId)
              .build();

      JWEObject jweObject = new JWEObject(header, new Payload(jsonPayload));
      jweObject.encrypt(new AESEncrypter(keyBytes));

      return jweObject.serialize();
    } catch (JOSEException e) {
      throw new RuntimeException("Failed to encrypt payload as JWE: " + e.getMessage(), e);
    }
  }
}
