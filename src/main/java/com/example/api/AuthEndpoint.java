package com.example.api;

import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.annotations.http.Post;
import com.example.domain.KeyRotator;
import com.typesafe.config.Config;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

@HttpEndpoint()
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.INTERNET))
public class AuthEndpoint {

  private final KeyRotator keyRotator;
  private final String issuer;

  public AuthEndpoint(KeyRotator keyRotator, Config config) {
    this.keyRotator = keyRotator;
    issuer = config.getString("pretend-jwks.issuer");
  }

  @Post("/rotate")
  public akka.http.javadsl.model.HttpResponse rotate() {
    keyRotator.rotate();
    return akka.javasdk.http.HttpResponses.ok();
  }

  @Post("/auth")
  public TokenResponse auth(AuthRequest request) {
    try {
      var current = keyRotator.current();
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
      sig.initSign(current.keyPair().getPrivate());
      sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
      String signature = encoder.encodeToString(sig.sign());

      return new TokenResponse(signingInput + "." + signature);
    } catch (Exception e) {
      throw new RuntimeException("Failed to sign JWT", e);
    }
  }

  @Get("/.well-known/jwks.json")
  public JwksResponse getJwks() {
    var encoder = Base64.getUrlEncoder().withoutPadding();
    var jwkKeys = keyRotator.all().stream().map(entry -> {
      var rsaPublicKey = (RSAPublicKey) entry.keyPair().getPublic();
      String n = encoder.encodeToString(unsignedBytes(rsaPublicKey.getModulus().toByteArray()));
      String e = encoder.encodeToString(unsignedBytes(rsaPublicKey.getPublicExponent().toByteArray()));
      return new JwkKey("RSA", "sig", "RS256", entry.kid(), n, e);
    }).toList();
    return new JwksResponse(jwkKeys);
  }

  @Get("/.well-known/openid-configuration")
  public OpenIdConfiguration getOpenIdConfiguration() {
    var publicHostname = System.getenv("PUBLIC_HOSTNAME");
    if (publicHostname == null) {
      throw new RuntimeException("Environment variable PUBLIC_HOSTNAME not set");
    }
    return new OpenIdConfiguration("https://" + publicHostname + "/.well-known/jwks.json");
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
