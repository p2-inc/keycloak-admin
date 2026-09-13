package io.phasetwo.keycloak.admin;

/**
 * Produces the {@code client_assertion} used to authenticate a client to the token endpoint, as
 * described in <a href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523</a>.
 *
 * <p>Implementations are called once per token request, so the assertion can -- and should -- carry
 * a unique {@code jti} and a short {@code exp}.
 *
 * <p>{@link PrivateKeyJwt} is the built-in implementation for the common case of signing with a
 * local private key. Implementing this interface directly is the way to sign somewhere the key
 * cannot be exported from, such as an HSM or a cloud KMS.
 */
@FunctionalInterface
public interface ClientAssertionProvider {

  /**
   * Builds a signed JWT to send as the {@code client_assertion} form parameter.
   *
   * @param context the endpoint the assertion is for
   * @return the serialized JWT
   */
  String assertion(ClientAssertionContext context);
}
