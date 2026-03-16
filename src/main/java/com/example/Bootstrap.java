package com.example;

import akka.javasdk.DependencyProvider;
import akka.javasdk.ServiceSetup;
import akka.javasdk.annotations.Setup;
import com.example.domain.KeyRotator;
import com.typesafe.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Setup
public class Bootstrap implements ServiceSetup {

  private final Logger logger = LoggerFactory.getLogger(getClass());
  private final KeyRotator keyRotator;
  private final Duration rotationInterval;

  public Bootstrap(Config config) {
    this.keyRotator = new KeyRotator();
    this.rotationInterval = config.getDuration("pretend-jwks.key-rotation-interval");
    logger.info("Key rotation interval: {}", rotationInterval);
  }

  @Override
  public void onStartup() {
    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "key-rotator");
      t.setDaemon(true);
      return t;
    });
    long intervalMillis = rotationInterval.toMillis();
    scheduler.scheduleAtFixedRate(keyRotator::rotate, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS);
    logger.info("Key rotation scheduled every {}", rotationInterval);
  }

  @Override
  public DependencyProvider createDependencyProvider() {
    return new DependencyProvider() {
      @Override
      public <T> T getDependency(Class<T> clazz) {
        if (clazz == KeyRotator.class) {
          return clazz.cast(keyRotator);
        }
        throw new RuntimeException("No such dependency: " + clazz);
      }
    };
  }
}
