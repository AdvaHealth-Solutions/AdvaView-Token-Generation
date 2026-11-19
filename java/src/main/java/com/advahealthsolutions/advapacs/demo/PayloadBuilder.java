package com.advahealthsolutions.advapacs.demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.*;

/**
 * Builds the JSON payload (the "claims") carried inside an AdvaView launch token.
 *
 * <p>Fields:
 *
 * <ul>
 *   <li>{@code username} - the user the token is issued to.
 *   <li>{@code patientId} - only present when studies are identified by accession number.
 *   <li>{@code studies} - the studies the user may open. Each entry contains either a {@code
 *       studyInstanceUid} or an {@code accessionNumber}.
 *   <li>{@code expiresAt} - when the token stops being accepted, in seconds since the Unix epoch
 *       (UTC).
 *   <li>{@code jti} - a unique ID for this token. Generate a new random value for every token; it
 *       lets AdvaPACS reject a token that is presented more than once.
 * </ul>
 */
public class PayloadBuilder {

  private final ObjectMapper objectMapper = new ObjectMapper();

  public String buildJson(Config config) {
    Map<String, Object> payload = new HashMap<>();

    payload.put("username", config.getUsername());

    List<Map<String, Object>> studies = new ArrayList<>();

    if (config.getPatientId() != null) {
      // Identify studies by patient ID + accession number.
      payload.put("patientId", config.getPatientId());
      for (String accNum : config.getAccNums()) {
        studies.add(Map.of("accessionNumber", accNum));
      }
    } else {
      // Identify studies by Study Instance UID.
      for (String suid : config.getSuids()) {
        studies.add(Map.of("studyInstanceUid", suid));
      }
    }

    payload.put("studies", studies);

    // Absolute expiry time as epoch seconds (not a duration).
    payload.put("expiresAt", Instant.now().plusSeconds(config.getExpireAfter()).getEpochSecond());

    // Unique, single-use token ID.
    payload.put("jti", UUID.randomUUID().toString());

    try {
      return objectMapper.writeValueAsString(payload);
    } catch (JsonProcessingException e) {
      throw new RuntimeException("Failed to serialize JSON payload", e);
    }
  }
}
