package com.example.api;

import akka.http.javadsl.model.ContentTypes;
import akka.http.javadsl.model.HttpHeader;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.headers.RawHeader;
import akka.javasdk.JsonSupport;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import com.example.application.KeyPairEntity;
import com.example.domain.KeyPairState;
import com.typesafe.config.Config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@HttpEndpoint()
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.INTERNET))
public class AuthEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient componentClient;
  private final String issuer;
  private final Duration rotationInterval;

  public AuthEndpoint(ComponentClient componentClient, Config config) {
    this.componentClient = componentClient;
    issuer = config.getString("pretend-jwks.issuer");
    rotationInterval = config.getDuration("pretend-jwks.key-rotation-interval");
  }

  @Get("/")
  public akka.http.javadsl.model.HttpResponse index() {
    return HttpResponses.staticResource("index.html");
  }

  @Post("/rotate")
  public akka.http.javadsl.model.HttpResponse rotate() {
    var newEntry = KeyPairState.KeyEntry.generate();
    componentClient.forKeyValueEntity(KeyPairEntity.ENTITY_ID)
        .method(KeyPairEntity::rotate)
        .invoke(newEntry);
    return akka.javasdk.http.HttpResponses.ok();
  }

  @Post("/auth")
  public TokenResponse auth(AuthRequest request) {
    try {
      var state = componentClient.forKeyValueEntity(KeyPairEntity.ENTITY_ID)
          .method(KeyPairEntity::get)
          .invoke();
      var current = state.current();
      var encoder = Base64.getUrlEncoder().withoutPadding();
      var now = Instant.now();

      String header = encoder.encodeToString(
          ("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + current.kid() + "\"}").getBytes(StandardCharsets.UTF_8));

      String subject = (request != null && request.subject() != null) ? request.subject() : "anonymous";
      long iat = now.getEpochSecond();
      long exp = now.plusSeconds(3600).getEpochSecond();
      String payload = encoder.encodeToString(
          ("{\"sub\":\"" + subject + "\",\"iss\":\"" + issuer + "\",\"iat\":" + iat + ",\"exp\":" + exp + "}").getBytes(StandardCharsets.UTF_8));

      String signingInput = header + "." + payload;
      Signature sig = Signature.getInstance("SHA256withRSA");
      sig.initSign(current.privateKey());
      sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
      String signature = encoder.encodeToString(sig.sign());

      return new TokenResponse(signingInput + "." + signature);
    } catch (Exception e) {
      throw new RuntimeException("Failed to sign JWT", e);
    }
  }

  @Get("/.well-known/jwks.json")
  public HttpResponse getJwks() {
    var state = componentClient.forKeyValueEntity(KeyPairEntity.ENTITY_ID)
        .method(KeyPairEntity::get)
        .invoke();
    var encoder = Base64.getUrlEncoder().withoutPadding();
    var jwkKeys = state.allEntries().stream().map(entry -> {
      var rsaPublicKey = entry.publicKey();
      String n = encoder.encodeToString(unsignedBytes(rsaPublicKey.getModulus().toByteArray()));
      String e = encoder.encodeToString(unsignedBytes(rsaPublicKey.getPublicExponent().toByteArray()));
      return new JwkKey("RSA", "sig", "RS256", entry.kid(), n, e);
    }).toList();

    String json = JsonSupport.encodeToString(new JwksResponse(jwkKeys));
    String etag = "\"" + sha256Hex(json) + "\"";
    long maxAge = rotationInterval.toSeconds();

    HttpHeader cacheControl = RawHeader.create("Cache-Control", "public, max-age=" + maxAge);
    HttpHeader etagHeader = RawHeader.create("ETag", etag);

    var ifNoneMatch = requestContext().requestHeader("If-None-Match").map(HttpHeader::value);
    if (ifNoneMatch.map(v -> v.equals(etag)).orElse(false)) {
      return HttpResponse.create()
          .withStatus(304)
          .addHeader(cacheControl)
          .addHeader(etagHeader);
    }

    return HttpResponse.create()
        .withStatus(200)
        .withEntity(ContentTypes.APPLICATION_JSON, json)
        .addHeader(cacheControl)
        .addHeader(etagHeader);
  }

  @Get("/.well-known/openid-configuration")
  public OpenIdConfiguration getOpenIdConfiguration() {
    var publicHostname = System.getenv("PUBLIC_HOSTNAME");
    if (publicHostname == null) {
      throw new RuntimeException("Environment variable PUBLIC_HOSTNAME not set");
    }
    return new OpenIdConfiguration("https://" + publicHostname + "/.well-known/jwks.json");
  }

  private String sha256Hex(String input) {
    try {
      var digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (Exception e) {
      throw new RuntimeException("Failed to compute SHA-256", e);
    }
  }

  /** Strip the leading zero byte that BigInteger.toByteArray() adds for positive numbers. */
  private byte[] unsignedBytes(byte[] bytes) {
    if (bytes.length > 1 && bytes[0] == 0) {
      byte[] stripped = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, stripped, 0, stripped.length);
      return stripped;
    }
    return bytes;
  }

  public record JwkKey(String kty, String use, String alg, String kid, String n, String e) {}
  public record JwksResponse(List<JwkKey> keys) {}
  public record OpenIdConfiguration(String jwks_uri) {}
  public record AuthRequest(String subject) {}
  public record TokenResponse(String token) {}
}
