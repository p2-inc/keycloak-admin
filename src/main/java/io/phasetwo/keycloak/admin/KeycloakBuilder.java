package io.phasetwo.keycloak.admin;

import static org.keycloak.OAuth2Constants.PASSWORD;

import org.apache.http.client.HttpClient;
import org.keycloak.admin.client.Config;

public class KeycloakBuilder {
  private String serverUrl;
  private String realm;
  private String username;
  private String password;
  private String clientId;
  private String clientSecret;
  private String grantType;
  private HttpClient httpClient;
  private String authorization;
  private String scope;

  private KeycloakBuilder() {}

  public static KeycloakBuilder builder() {
    return new KeycloakBuilder();
  }

  public KeycloakBuilder serverUrl(String serverUrl) {
    this.serverUrl = serverUrl;
    return this;
  }

  public KeycloakBuilder realm(String realm) {
    this.realm = realm;
    return this;
  }

  public KeycloakBuilder grantType(String grantType) {
    Config.checkGrantType(grantType);
    this.grantType = grantType;
    return this;
  }

  public KeycloakBuilder username(String username) {
    this.username = username;
    return this;
  }

  public KeycloakBuilder password(String password) {
    this.password = password;
    return this;
  }

  public KeycloakBuilder clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  public KeycloakBuilder clientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  public KeycloakBuilder authorization(String authorization) {
    this.authorization = authorization;
    return this;
  }

  public KeycloakBuilder scope(String scope) {
    this.scope = scope;
    return this;
  }

  public KeycloakBuilder httpClient(HttpClient httpClient) {
    this.httpClient = httpClient;
    return this;
  }

  public Keycloak build() {
    if (serverUrl == null) {
      throw new IllegalStateException("serverUrl required");
    }
    if (realm == null) {
      throw new IllegalStateException("realm required");
    }
    if (authorization == null && grantType == null) {
      grantType = PASSWORD;
    }
    if (PASSWORD.equals(grantType)) {
      if (username == null) {
        throw new IllegalStateException("username required");
      }
      if (password == null) {
        throw new IllegalStateException("password required");
      }
    }
    if (authorization == null && clientId == null) {
      throw new IllegalStateException("clientId required");
    }
    return new Keycloak(
        serverUrl,
        realm,
        username,
        password,
        clientId,
        clientSecret,
        grantType,
        httpClient,
        authorization,
        scope);
  }
}
