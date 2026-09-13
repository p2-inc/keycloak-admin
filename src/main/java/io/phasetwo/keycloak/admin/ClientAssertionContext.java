package io.phasetwo.keycloak.admin;

/**
 * The details of the endpoint a client assertion is being generated for.
 *
 * <p>Passed to a {@link ClientAssertionProvider} so it can build a correctly scoped assertion. A
 * new context is created for every request, so providers must not cache assertions across calls --
 * an assertion carries a {@code jti} and a short {@code exp} and is intended to be single-use.
 *
 * @param serverUrl the base URL of the Keycloak server, without a trailing slash
 * @param realm the realm the request is being made against
 * @param clientId the client ID authenticating, which is also the expected {@code iss} and {@code
 *     sub} of the assertion
 * @param endpointUrl the absolute URL of the endpoint being called, e.g. the token endpoint
 */
public record ClientAssertionContext(
    String serverUrl, String realm, String clientId, String endpointUrl) {

  /**
   * The realm's issuer URL.
   *
   * <p>Keycloak accepts either this or {@link #endpointUrl()} as the assertion audience, but only
   * one of them -- an assertion carrying both is rejected.
   *
   * @return the issuer URL for {@link #realm()}
   */
  public String realmIssuerUrl() {
    return serverUrl + "/realms/" + realm;
  }
}
