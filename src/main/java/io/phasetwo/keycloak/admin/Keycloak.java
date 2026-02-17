package io.phasetwo.keycloak.admin;

import static org.keycloak.OAuth2Constants.PASSWORD;

import io.phasetwo.keycloak.admin.resource.ResourceProxyFactory;
import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.admin.client.Config;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.admin.client.resource.ServerInfoResource;

public class Keycloak implements AutoCloseable {

  private final Config config;
  private final HttpClient client;
  private final boolean ownClient;
  private final TokenManager tokenManager;
  private final String authToken;
  private boolean closed;

  Keycloak(
      String serverUrl,
      String realm,
      String username,
      String password,
      String clientId,
      String clientSecret,
      String grantType,
      HttpClient httpClient,
      String authToken,
      String scope) {
    this.config =
        new Config(serverUrl, realm, username, password, clientId, clientSecret, grantType, scope);
    this.client = httpClient != null ? httpClient : HttpClients.createDefault();
    this.ownClient = httpClient == null;
    this.authToken = authToken;
    this.tokenManager = authToken == null ? new TokenManager(config, this.client) : null;
  }

  public static Keycloak getInstance(
      String serverUrl,
      String realm,
      String username,
      String password,
      String clientId,
      String clientSecret) {
    return new Keycloak(
        serverUrl, realm, username, password, clientId, clientSecret, PASSWORD, null, null, null);
  }

  public static Keycloak getInstance(
      String serverUrl, String realm, String clientId, String authToken) {
    return new Keycloak(
        serverUrl, realm, null, null, clientId, null, PASSWORD, null, authToken, null);
  }

  public RealmsResource realms() {
    return ResourceProxyFactory.create(
        RealmsResource.class,
        config.getServerUrl(),
        client,
        this::resolveAccessToken,
        this::invalidateToken);
  }

  public RealmResource realm(String realmName) {
    return realms().realm(realmName);
  }

  public ServerInfoResource serverInfo() {
    return ResourceProxyFactory.create(
        ServerInfoResource.class,
        config.getServerUrl(),
        client,
        this::resolveAccessToken,
        this::invalidateToken);
  }

  public TokenManager tokenManager() {
    return tokenManager;
  }

  public <T> T proxy(Class<T> proxyClass, URI absoluteURI) {
    return ResourceProxyFactory.create(
        proxyClass,
        absoluteURI.toString(),
        client,
        this::resolveAccessToken,
        this::invalidateToken);
  }

  @Override
  public void close() {
    closed = true;
    if (tokenManager != null) {
      try {
        tokenManager.logout();
      } catch (RuntimeException ignored) {
        // best-effort logout only
      }
    }
    if (ownClient && client instanceof Closeable closeable) {
      try {
        closeable.close();
      } catch (IOException ignored) {
        // best-effort close only
      }
    }
  }

  public boolean isClosed() {
    return closed;
  }

  private String resolveAccessToken() {
    if (authToken != null) {
      return authToken;
    }
    return tokenManager.getAccessTokenString();
  }

  private void invalidateToken(String token) {
    if (tokenManager != null) {
      tokenManager.invalidate(token);
    }
  }
}
