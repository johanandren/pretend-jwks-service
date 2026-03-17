package com.example.domain;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public record KeyPairState(KeyEntry current, Optional<KeyEntry> previous) {

  public record KeyEntry(String kid, byte[] privateKeyEncoded, byte[] publicKeyEncoded) {

    public static KeyEntry generate() {
      try {
        var gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        var kp = gen.generateKeyPair();
        var kid = "key-" + Instant.now().getEpochSecond();
        return new KeyEntry(kid, kp.getPrivate().getEncoded(), kp.getPublic().getEncoded());
      } catch (Exception e) {
        throw new RuntimeException("Failed to generate RSA key pair", e);
      }
    }

    public PrivateKey privateKey() {
      try {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
      } catch (Exception e) {
        throw new RuntimeException("Failed to decode private key", e);
      }
    }

    public RSAPublicKey publicKey() {
      try {
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
      } catch (Exception e) {
        throw new RuntimeException("Failed to decode public key", e);
      }
    }
  }

  public static KeyPairState initial(KeyEntry entry) {
    return new KeyPairState(entry, Optional.empty());
  }

  public KeyPairState rotate(KeyEntry newEntry) {
    return new KeyPairState(newEntry, Optional.of(current));
  }

  public List<KeyEntry> allEntries() {
    var entries = new ArrayList<KeyEntry>();
    entries.add(current);
    previous.ifPresent(entries::add);
    return entries;
  }
}
