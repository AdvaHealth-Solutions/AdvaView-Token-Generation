package com.advahealthsolutions.advapacs.demo;

import java.util.ArrayList;
import java.util.List;

/**
 * The inputs needed to generate an AdvaView launch token.
 *
 * <p>Studies can be identified in one of two ways (but not both):
 *
 * <ul>
 *   <li><b>By Study Instance UID</b> - one or more {@code suid} values.
 *   <li><b>By patient and accession number</b> - a {@code patientId} together with one or more
 *       {@code accNum} values.
 * </ul>
 */
public class Config {

  /** DICOM Study Instance UIDs the user may open. */
  private final List<String> suids = new ArrayList<>();

  /** Patient identifier; used together with {@link #accNums}. */
  private String patientId;

  /** Accession numbers (belonging to {@link #patientId}) the user may open. */
  private final List<String> accNums = new ArrayList<>();

  /** The user the token is issued to, as known to AdvaPACS. */
  private String username;

  /** How the payload is protected. Defaults to JWE (encrypted), the recommended mode. */
  private JoseMode mode = JoseMode.JWE;

  /** Identifies which access key was used; sent in the token header as {@code kid}. */
  private String accessKeyId;

  /** The shared secret for the access key. Keep this server-side; never send it to a browser. */
  private String accessKeySecret;

  /** Token lifetime in seconds from now. Keep this short (e.g. a few minutes). */
  private Integer expireAfter;

  public List<String> getSuids() {
    return suids;
  }

  public void addSuid(String suid) {
    if (suid != null) {
      this.suids.add(suid);
    }
  }

  public String getPatientId() {
    return patientId;
  }

  public void setPatientId(String patientId) {
    this.patientId = patientId;
  }

  public List<String> getAccNums() {
    return accNums;
  }

  public void addAccNum(String accNum) {
    if (accNum != null) {
      this.accNums.add(accNum);
    }
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public JoseMode getMode() {
    return mode;
  }

  public void setMode(JoseMode mode) {
    this.mode = mode;
  }

  public String getAccessKeySecret() {
    return accessKeySecret;
  }

  public void setAccessKeySecret(String accessKeySecret) {
    this.accessKeySecret = accessKeySecret;
  }

  public String getAccessKeyId() {
    return accessKeyId;
  }

  public void setAccessKeyId(String accessKeyId) {
    this.accessKeyId = accessKeyId;
  }

  public Integer getExpireAfter() {
    return expireAfter;
  }

  public void setExpireAfter(Integer expireAfter) {
    this.expireAfter = expireAfter;
  }

  /** Checks the rules every token must satisfy. */
  public void validate() {
    if (username == null || username.isEmpty()) {
      throw new IllegalArgumentException("username is required");
    }

    if (expireAfter == null || expireAfter <= 0) {
      throw new IllegalArgumentException("expireAfter is required and must be a positive number of seconds");
    }

    boolean identifiedBySuid = !suids.isEmpty();
    boolean identifiedByAccession = patientId != null && !patientId.isEmpty() && !accNums.isEmpty();

    // Exactly one way of identifying studies must be used.
    if (identifiedBySuid == identifiedByAccession) {
      throw new IllegalArgumentException(
          "You must provide either:\n"
              + "  • At least one --suid\n"
              + "    OR\n"
              + "  • --patientId AND at least one --accNum\n"
              + "These options are mutually exclusive.");
    }
  }
}
