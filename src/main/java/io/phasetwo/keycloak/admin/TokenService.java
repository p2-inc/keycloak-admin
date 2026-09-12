package io.phasetwo.keycloak.admin;

import static org.keycloak.OAuth2Constants.CLIENT_ASSERTION;
import static org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE;
import static org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT;

import jakarta.ws.rs.WebApplicationException;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import org.apache.http.client.HttpClient;
import org.keycloak.admin.client.Config;
import org.keycloak.representations.AccessTokenResponse;

public class TokenService {

  private final Config config;
  private final HttpClient client;
  private final Duration socketTimeout;
  private final Duration connectTimeout;
  private final Duration connectionRequestTimeout;
  private final ClientAssertionProvider clientAssertion;

  public TokenService(
      Config config,
      HttpClient client,
      Duration socketTimeout,
      Duration connectTimeout,
      Duration connectionRequestTimeout) {
    this(config, client, socketTimeout, connectTimeout, connectionRequestTimeout, null);
  }

  public TokenService(
      Config config,
      HttpClient client,
      Duration socketTimeout,
      Duration connectTimeout,
      Duration connectionRequestTimeout,
      ClientAssertionProvider clientAssertion) {
    this.config = config;
    this.client = client;
    this.socketTimeout = socketTimeout;
    this.connectTimeout = connectTimeout;
    this.connectionRequestTimeout = connectionRequestTimeout;
    this.clientAssertion = clientAssertion;
  }

  public AccessTokenResponse grantToken(String realm, Map<String, String> formParams) {
    return tokenRequest("/realms/" + realm + "/protocol/openid-connect/token", formParams);
  }

  public AccessTokenResponse refreshToken(String realm, Map<String, String> formParams) {
    return tokenRequest("/realms/" + realm + "/protocol/openid-connect/token", formParams);
  }

  public void logout(String realm, Map<String, String> formParams) {
    String url = config.getServerUrl() + "/realms/" + realm + "/protocol/openid-connect/logout";
    Http request = withTimeouts(Http.doPost(url, client).acceptJson());
    addAuth(request, url);
    addFormParams(request, formParams);
    try (Http.Response response = request.asResponse()) {
      if (response.getStatus() >= 400) {
        throw new WebApplicationException(
            buildErrorMessage(response.getStatus(), response.asString()), response.getStatus());
      }
    } catch (IOException e) {
      throw new IllegalStateException("Failed to call logout endpoint", e);
    }
  }

  private AccessTokenResponse tokenRequest(String path, Map<String, String> formParams) {
    String url = config.getServerUrl() + path;
    Http request = withTimeouts(Http.doPost(url, client).acceptJson());
    addAuth(request, url);
    addFormParams(request, formParams);
    try (Http.Response response = request.asResponse()) {
      if (response.getStatus() >= 400) {
        throw new WebApplicationException(
            buildErrorMessage(response.getStatus(), response.asString()), response.getStatus());
      }
      return response.asJson(AccessTokenResponse.class);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to call token endpoint", e);
    }
  }

  private Http withTimeouts(Http request) {
    return request
        .socketTimeout(socketTimeout)
        .connectTimeout(connectTimeout)
        .connectionRequestTimeout(connectionRequestTimeout);
  }

  private void addAuth(Http request, String url) {
    if (clientAssertion != null) {
      // A fresh assertion per request: it carries a jti and a short exp, so reusing one across
      // requests is what replay protection on the server side is there to reject.
      String assertion =
          clientAssertion.assertion(
              new ClientAssertionContext(
                  config.getServerUrl(), config.getRealm(), config.getClientId(), url));
      request.param(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_JWT);
      request.param(CLIENT_ASSERTION, assertion);
      return;
    }
    if (!config.isPublicClient()) {
      request.authBasic(config.getClientId(), config.getClientSecret());
    }
  }

  private void addFormParams(Http request, Map<String, String> formParams) {
    if (formParams == null) {
      return;
    }
    for (Map.Entry<String, String> formParam : formParams.entrySet()) {
      if (formParam.getValue() != null) {
        request.param(formParam.getKey(), formParam.getValue());
      }
    }
  }

  private static String buildErrorMessage(int status, String body) {
    if (body != null && !body.isBlank()) {
      return "HTTP " + status + ": " + body;
    }
    return "HTTP " + status;
  }
}
