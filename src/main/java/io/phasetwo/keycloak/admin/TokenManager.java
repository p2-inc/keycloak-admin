package io.phasetwo.keycloak.admin;

import static org.keycloak.OAuth2Constants.CLIENT_ID;
import static org.keycloak.OAuth2Constants.GRANT_TYPE;
import static org.keycloak.OAuth2Constants.PASSWORD;
import static org.keycloak.OAuth2Constants.REFRESH_TOKEN;
import static org.keycloak.OAuth2Constants.SCOPE;
import static org.keycloak.OAuth2Constants.USERNAME;

import jakarta.ws.rs.WebApplicationException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.http.client.HttpClient;
import org.keycloak.admin.client.Config;
import org.keycloak.representations.AccessTokenResponse;

public class TokenManager {
  private static final long DEFAULT_MIN_VALIDITY = 30L;

  private final Config config;
  private final TokenService tokenService;
  private final String accessTokenGrantType;

  private AccessTokenResponse currentToken;
  private long expirationTime;
  private long refreshExpirationTime;
  private long minTokenValidity = DEFAULT_MIN_VALIDITY;

  public TokenManager(Config config, HttpClient client) {
    this.config = config;
    this.tokenService = new TokenService(config, client);
    this.accessTokenGrantType = config.getGrantType();
  }

  public String getAccessTokenString() {
    return getAccessToken().getToken();
  }

  public synchronized AccessTokenResponse getAccessToken() {
    if (currentToken == null) {
      grantToken();
    } else if (tokenExpired()) {
      refreshToken();
    }
    return currentToken;
  }

  public AccessTokenResponse grantToken() {
    Map<String, String> form = new LinkedHashMap<>();
    form.put(GRANT_TYPE, accessTokenGrantType);
    if (PASSWORD.equals(accessTokenGrantType)) {
      form.put(USERNAME, config.getUsername());
      form.put(PASSWORD, config.getPassword());
    }
    if (config.getScope() != null) {
      form.put(SCOPE, config.getScope());
    }
    if (config.isPublicClient()) {
      form.put(CLIENT_ID, config.getClientId());
    }

    long requestTime = now();
    synchronized (this) {
      currentToken = tokenService.grantToken(config.getRealm(), form);
      expirationTime = requestTime + currentToken.getExpiresIn();
      refreshExpirationTime = requestTime + currentToken.getRefreshExpiresIn();
    }
    return currentToken;
  }

  public synchronized AccessTokenResponse refreshToken() {
    if (currentToken == null || currentToken.getRefreshToken() == null || refreshTokenExpired()) {
      return grantToken();
    }

    Map<String, String> form = new LinkedHashMap<>();
    form.put(GRANT_TYPE, REFRESH_TOKEN);
    form.put(REFRESH_TOKEN, currentToken.getRefreshToken());
    if (config.isPublicClient()) {
      form.put(CLIENT_ID, config.getClientId());
    }

    try {
      long requestTime = now();
      currentToken = tokenService.refreshToken(config.getRealm(), form);
      expirationTime = requestTime + currentToken.getExpiresIn();
      return currentToken;
    } catch (WebApplicationException e) {
      return grantToken();
    }
  }

  public synchronized void logout() {
    if (currentToken == null || currentToken.getRefreshToken() == null || refreshTokenExpired()) {
      return;
    }
    Map<String, String> form = new LinkedHashMap<>();
    form.put(REFRESH_TOKEN, currentToken.getRefreshToken());
    if (config.isPublicClient()) {
      form.put(CLIENT_ID, config.getClientId());
    }
    tokenService.logout(config.getRealm(), form);
    currentToken = null;
  }

  public synchronized void setMinTokenValidity(long minTokenValidity) {
    this.minTokenValidity = minTokenValidity;
  }

  public synchronized void invalidate(String token) {
    if (currentToken == null) {
      return;
    }
    if (token.equals(currentToken.getToken())) {
      expirationTime = -1;
    }
  }

  private synchronized boolean tokenExpired() {
    return (now() + minTokenValidity) >= expirationTime;
  }

  private synchronized boolean refreshTokenExpired() {
    return (now() + minTokenValidity) >= refreshExpirationTime;
  }

  private static long now() {
    return Instant.now().getEpochSecond();
  }
}
