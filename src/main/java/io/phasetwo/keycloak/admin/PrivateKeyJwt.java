package io.phasetwo.keycloak.admin;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.JsonWebToken;

/**
 * A {@link ClientAssertionProvider} that signs assertions with a local private key -- {@code
 * private_key_jwt} client authentication.
 *
 * <p>The matching public key must be configured on the Keycloak client, whose client authenticator
 * must be set to {@code client-jwt}.
 *
 * <pre>{@code
 * Keycloak keycloak = KeycloakBuilder.builder()
 *     .serverUrl("https://keycloak.example.com")
 *     .realm("my-realm")
 *     .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
 *     .clientId("my-client")
 *     .clientAssertion(PrivateKeyJwt.with(privateKey).keyId("my-key-1"))
 *     .build();
 * }</pre>
 *
 * <p>Instances are immutable; the configuration methods return a new instance. They are safe to
 * share between threads and to reuse across requests -- each call to {@link
 * #assertion(ClientAssertionContext)} mints a fresh assertion.
 */
public class PrivateKeyJwt implements ClientAssertionProvider {

  /** Assertions are valid for this long unless {@link #lifespan(Duration)} says otherwise. */
  public static final Duration DEFAULT_LIFESPAN = Duration.ofSeconds(60);

  private final PrivateKey privateKey;
  private final String algorithm;
  private final String keyId;
  private final Duration lifespan;
  private final String audience;

  private PrivateKeyJwt(
      PrivateKey privateKey, String algorithm, String keyId, Duration lifespan, String audience) {
    this.privateKey = privateKey;
    this.algorithm = algorithm;
    this.keyId = keyId;
    this.lifespan = lifespan;
    this.audience = audience;
  }

  /**
   * Signs with the given key using {@code RS256}.
   *
   * @param privateKey the client's private key
   * @return a new provider
   */
  public static PrivateKeyJwt with(PrivateKey privateKey) {
    if (privateKey == null) {
      throw new IllegalArgumentException("privateKey required");
    }
    return new PrivateKeyJwt(privateKey, Algorithm.RS256, null, DEFAULT_LIFESPAN, null);
  }

  /**
   * Signs with a PEM-encoded private key using {@code RS256}.
   *
   * @param pem the private key, with or without the PEM header and footer
   * @return a new provider
   */
  public static PrivateKeyJwt withPem(String pem) {
    if (pem == null || pem.isBlank()) {
      throw new IllegalArgumentException("pem required");
    }
    return with(PemUtils.decodePrivateKey(pem));
  }

  /**
   * Sets the JWS algorithm. Must match the key type -- {@code RS*}/{@code PS*} for an RSA key,
   * {@code ES*} for an EC key.
   *
   * @param algorithm a JWS algorithm name, e.g. one of the constants on {@link Algorithm}
   * @return a new provider with the algorithm applied
   */
  public PrivateKeyJwt algorithm(String algorithm) {
    if (algorithm == null || algorithm.isBlank()) {
      throw new IllegalArgumentException("algorithm required");
    }
    return new PrivateKeyJwt(privateKey, algorithm, keyId, lifespan, audience);
  }

  /**
   * Sets the {@code kid} written into the JWS header.
   *
   * <p>Worth setting whenever the client's public keys come from a JWKS that holds, or may come to
   * hold, more than one key: without a {@code kid} the server has to try each key in turn, and a
   * rotation that publishes the new key alongside the old is exactly when that matters.
   *
   * @param keyId the key ID
   * @return a new provider with the key ID applied
   */
  public PrivateKeyJwt keyId(String keyId) {
    return new PrivateKeyJwt(privateKey, algorithm, keyId, lifespan, audience);
  }

  /**
   * Sets how long an assertion is valid for. Defaults to {@link #DEFAULT_LIFESPAN}.
   *
   * <p>Keep this short. The assertion is sent on every token request, so nothing needs it to
   * outlive the request it was minted for, and a short window limits what a captured assertion is
   * worth.
   *
   * @param lifespan a positive duration
   * @return a new provider with the lifespan applied
   */
  public PrivateKeyJwt lifespan(Duration lifespan) {
    if (lifespan == null || lifespan.isNegative() || lifespan.isZero()) {
      throw new IllegalArgumentException("lifespan must be positive");
    }
    return new PrivateKeyJwt(privateKey, algorithm, keyId, lifespan, audience);
  }

  /**
   * Overrides the assertion audience, which defaults to the realm issuer URL.
   *
   * <p>Keycloak accepts either the realm issuer URL or the URL of the endpoint being called, but
   * rejects an assertion carrying more than one audience with {@code "Multiple audiences not
   * allowed"} -- hence a single value rather than a list.
   *
   * @param audience the audience value
   * @return a new provider with the audience applied
   */
  public PrivateKeyJwt audience(String audience) {
    if (audience == null || audience.isBlank()) {
      throw new IllegalArgumentException("audience required");
    }
    return new PrivateKeyJwt(privateKey, algorithm, keyId, lifespan, audience);
  }

  @Override
  public String assertion(ClientAssertionContext context) {
    long now = Instant.now().getEpochSecond();

    JsonWebToken token = new JsonWebToken();
    token.id(UUID.randomUUID().toString());
    token.issuer(context.clientId());
    token.subject(context.clientId());
    token.audience(audience != null ? audience : context.realmIssuerUrl());
    token.iat(now);
    token.exp(now + lifespan.toSeconds());

    return new JWSBuilder().type("JWT").kid(keyId).jsonContent(token).sign(signer());
  }

  private SignatureSignerContext signer() {
    KeyWrapper key = new KeyWrapper();
    key.setAlgorithm(algorithm);
    key.setType(privateKey.getAlgorithm());
    key.setPrivateKey(privateKey);
    if (keyId != null) {
      key.setKid(keyId);
    }
    return new AsymmetricSignatureSignerContext(key);
  }
}
