package com.example.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.timer.TimerScheduler;
import akka.javasdk.timedaction.TimedAction;
import com.example.domain.KeyPairState;
import com.typesafe.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

@Component(id = "key-rotation")
public class KeyRotationTimedAction extends TimedAction {

  private final Logger logger = LoggerFactory.getLogger(getClass());
  private final ComponentClient componentClient;
  private final TimerScheduler timerScheduler;
  private final Duration rotationInterval;

  public KeyRotationTimedAction(ComponentClient componentClient, TimerScheduler timerScheduler, Config config) {
    this.componentClient = componentClient;
    this.timerScheduler = timerScheduler;
    this.rotationInterval = config.getDuration("pretend-jwks.key-rotation-interval");
  }

  public Effect rotate() {
    var newEntry = KeyPairState.KeyEntry.generate();
    componentClient.forKeyValueEntity(KeyPairEntity.ENTITY_ID)
        .method(KeyPairEntity::rotate)
        .invoke(newEntry);
    logger.info("RSA key rotated to kid: {}", newEntry.kid());
    timerScheduler.createSingleTimer(
        "key-rotation",
        rotationInterval,
        componentClient.forTimedAction().method(KeyRotationTimedAction::rotate).deferred()
    );
    return effects().done();
  }
}
