package io.phasetwo.keycloak.admin;

import jakarta.ws.rs.WebApplicationException;
import java.io.IOException;
import java.util.Map;
import org.apache.http.client.HttpClient;
import org.keycloak.admin.client.Config;
import org.keycloak.representations.AccessTokenResponse;

public class TokenService {

  private final Config config;
  private final HttpClient client;

  public TokenService(Config config, HttpClient client) {
    this.config = config;
    this.client = client;
  }

  public AccessTokenResponse grantToken(String realm, Map<String, String> formParams) {
    return tokenRequest("/realms/" + realm + "/protocol/openid-connect/token", formParams);
  }

  public AccessTokenResponse refreshToken(String realm, Map<String, String> formParams) {
    return tokenRequest("/realms/" + realm + "/protocol/openid-connect/token", formParams);
  }

  public void logout(String realm, Map<String, String> formParams) {
    String url = config.getServerUrl() + "/realms/" + realm + "/protocol/openid-connect/logout";
    Http request = Http.doPost(url, client).acceptJson();
    addAuth(request);
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
    Http request = Http.doPost(url, client).acceptJson();
    addAuth(request);
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

  private void addAuth(Http request) {
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
