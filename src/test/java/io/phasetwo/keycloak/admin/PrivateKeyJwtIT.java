package io.phasetwo.keycloak.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.DockerClientFactory;

/** Exercises {@code private_key_jwt} client authentication against a real Keycloak. */
@TestInstance(Lifecycle.PER_CLASS)
class PrivateKeyJwtIT {

  private KeycloakContainer keycloak;

  @BeforeAll
  void startContainer() {
    Assumptions.assumeTrue(
        DockerClientFactory.instance().isDockerAvailable(), "Docker is not available");
    keycloak =
        new KeycloakContainer("quay.io/keycloak/keycloak:26.5.3")
            .withAdminUsername("admin")
            .withAdminPassword("admin");
    keycloak.start();
  }

  @AfterAll
  void stopContainer() {
    if (keycloak != null) {
      keycloak.stop();
    }
  }

  @Test
  void shouldAuthenticateWithAssertionSignedByTheRegisteredKey() throws Exception {
    KeyPair keyPair = generateRsaKeyPair();
    String kid = UUID.randomUUID().toString();

    try (Fixture fixture = new Fixture(keyPair, kid)) {
      try (Keycloak client = fixture.clientFor(keyPair, kid)) {
        assertNotNull(client.tokenManager().getAccessTokenString());

        RealmRepresentation realm = client.realm(fixture.realmName).toRepresentation();
        assertEquals(fixture.realmName, realm.getRealm());
      }
    }
  }

  /**
   * The assertion is minted per request rather than cached, so a client that outlives one
   * assertion's lifespan keeps working. Without a fresh assertion the second call would be rejected
   * as expired or replayed.
   */
  @Test
  void shouldMintAFreshAssertionForEachTokenRequest() throws Exception {
    KeyPair keyPair = generateRsaKeyPair();
    String kid = UUID.randomUUID().toString();

    try (Fixture fixture = new Fixture(keyPair, kid)) {
      try (Keycloak client = fixture.clientFor(keyPair, kid)) {
        String first = client.tokenManager().grantToken().getToken();
        String second = client.tokenManager().grantToken().getToken();
        assertNotNull(first);
        assertNotNull(second);
      }
    }
  }

  @Test
  void shouldRejectAnAssertionSignedByADifferentKey() throws Exception {
    KeyPair registered = generateRsaKeyPair();
    KeyPair impostor = generateRsaKeyPair();
    String kid = UUID.randomUUID().toString();

    try (Fixture fixture = new Fixture(registered, kid)) {
      try (Keycloak client = fixture.clientFor(impostor, kid)) {
        WebApplicationException thrown =
            assertThrows(
                WebApplicationException.class, () -> client.tokenManager().getAccessTokenString());
        // Keycloak answers a bad assertion with 400 invalid_client, not 401.
        assertEquals(400, thrown.getResponse().getStatus());
        assertTrue(thrown.getMessage().contains("invalid_client"));
      }
    }
  }

  @Test
  void shouldRejectAClientSecretAndAnAssertionTogether() {
    IllegalStateException thrown =
        assertThrows(
            IllegalStateException.class,
            () ->
                KeycloakBuilder.builder()
                    .serverUrl("http://localhost:8080")
                    .realm("master")
                    .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                    .clientId("some-client")
                    .clientSecret("some-secret")
                    .clientAssertion(PrivateKeyJwt.with(generateRsaKeyPair().getPrivate()))
                    .build());
    assertTrue(thrown.getMessage().contains("mutually exclusive"));
  }

  /** A realm holding one {@code client-jwt} client whose service account is a realm admin. */
  private class Fixture implements AutoCloseable {

    private final String realmName = "pkjwt-" + UUID.randomUUID().toString().substring(0, 8);
    private final String clientId = "assertion-client";
    private final Keycloak admin = newAdminClient();

    Fixture(KeyPair keyPair, String kid) throws Exception {
      RealmRepresentation realm = new RealmRepresentation();
      realm.setRealm(realmName);
      realm.setEnabled(true);
      admin.realms().create(realm);

      RealmResource realmResource = admin.realm(realmName);
      ClientsResource clients = realmResource.clients();

      ClientRepresentation client = new ClientRepresentation();
      client.setClientId(clientId);
      client.setProtocol("openid-connect");
      client.setEnabled(true);
      client.setPublicClient(false);
      client.setServiceAccountsEnabled(true);
      client.setStandardFlowEnabled(false);
      client.setDirectAccessGrantsEnabled(false);
      client.setClientAuthenticatorType("client-jwt");
      client.setAttributes(
          Map.of(
              "use.jwks.string", "true",
              "jwks.string", jwks(keyPair, kid),
              "token.endpoint.auth.signing.alg", "RS256"));

      String uuid;
      try (Response response = clients.create(client)) {
        uuid = CreatedResponseUtil.getCreatedId(response);
      }

      String serviceUserId = clients.get(uuid).getServiceAccountUser().getId();
      String realmManagementId = clients.findByClientId("realm-management").get(0).getId();
      List<RoleRepresentation> realmAdmin =
          List.of(clients.get(realmManagementId).roles().get("realm-admin").toRepresentation());
      realmResource
          .users()
          .get(serviceUserId)
          .roles()
          .clientLevel(realmManagementId)
          .add(realmAdmin);
    }

    Keycloak clientFor(KeyPair keyPair, String kid) {
      return KeycloakBuilder.builder()
          .serverUrl(keycloak.getAuthServerUrl())
          .realm(realmName)
          .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
          .clientId(clientId)
          .clientAssertion(PrivateKeyJwt.with(keyPair.getPrivate()).keyId(kid))
          .build();
    }

    @Override
    public void close() {
      try {
        admin.realm(realmName).remove();
      } finally {
        admin.close();
      }
    }
  }

  private Keycloak newAdminClient() {
    return KeycloakBuilder.builder()
        .serverUrl(keycloak.getAuthServerUrl())
        .realm("master")
        .grantType(OAuth2Constants.PASSWORD)
        .username("admin")
        .password("admin")
        .clientId("admin-cli")
        .build();
  }

  private static String jwks(KeyPair keyPair, String kid) throws Exception {
    JWK jwk = JWKBuilder.create().kid(kid).rsa(keyPair.getPublic(), KeyUse.SIG);
    JSONWebKeySet keySet = new JSONWebKeySet();
    keySet.setKeys(new JWK[] {jwk});
    return JsonSerialization.writeValueAsString(keySet);
  }

  private static KeyPair generateRsaKeyPair() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      return generator.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
