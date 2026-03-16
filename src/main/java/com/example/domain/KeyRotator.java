package com.example.domain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the current and previous RSA key pairs.
 * Call {@link #rotate()} to generate a new key; the current key becomes the previous one
 * and is still included in the JWKS output for one rotation period so in-flight tokens
 * remain verifiable.
 */
public class KeyRotator {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public record KeyEntry(String kid, KeyPair keyPair) {}

  // Index 0 = current (used for signing), index 1 = previous (kept for verification only)
  private final AtomicReference<List<KeyEntry>> keys;

  public KeyRotator() {
    keys = new AtomicReference<>(List.of(generateEntry()));
    logger.info("Initial RSA key generated: {}", keys.get().get(0).kid());
  }

  /** Promote a new key to current and retire the one before previous. */
  public void rotate() {
    var newEntry = generateEntry();
    keys.getAndUpdate(current -> List.of(newEntry, current.get(0)));
    logger.info("RSA key rotated, new kid: {}", newEntry.kid());
  }

  /** The key currently used for signing new JWTs. */
  public KeyEntry current() {
    return keys.get().get(0);
  }

  /** All active keys (current + previous) to include in the JWKS response. */
  public List<KeyEntry> all() {
    return keys.get();
  }

  private KeyEntry generateEntry() {
    try {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      String kid = "key-" + Instant.now().getEpochSecond();
      return new KeyEntry(kid, gen.generateKeyPair());
    } catch (Exception e) {
      throw new RuntimeException("Failed to generate RSA key pair", e);
    }
  }
}
