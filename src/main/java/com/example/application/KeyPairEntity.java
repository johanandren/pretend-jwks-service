package com.example.application;

import akka.Done;
import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import com.example.domain.KeyPairState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(id = "key-pair")
public class KeyPairEntity extends KeyValueEntity<KeyPairState> {

  public static final String ENTITY_ID = "singleton";

  private final Logger logger = LoggerFactory.getLogger(getClass());

  /** Idempotent — no-op if already initialized. */
  public Effect<Done> initialize(KeyPairState.KeyEntry entry) {
    if (currentState() != null) {
      return effects().reply(Done.getInstance());
    }
    logger.info("Initializing key pair with kid: {}", entry.kid());
    return effects().updateState(KeyPairState.initial(entry)).thenReply(Done.getInstance());
  }

  /** Promote newEntry to current, demote current to previous. */
  public Effect<Done> rotate(KeyPairState.KeyEntry newEntry) {
    logger.info("Rotating to new key with kid: {}", newEntry.kid());
    if (currentState() == null) {
      return effects().updateState(KeyPairState.initial(newEntry)).thenReply(Done.getInstance());
    }
    return effects().updateState(currentState().rotate(newEntry)).thenReply(Done.getInstance());
  }

  public Effect<KeyPairState> get() {
    if (currentState() == null) {
      return effects().error("Key pair not initialized");
    }
    return effects().reply(currentState());
  }
}
