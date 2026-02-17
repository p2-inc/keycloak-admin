package io.phasetwo.keycloak.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.DockerClientFactory;

@TestInstance(Lifecycle.PER_CLASS)
class KeycloakContainerIT {

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

  @Test
  void shouldQueryRealms() {
    try (Keycloak client = newAdminClient()) {
      List<RealmRepresentation> realms = client.realms().findAll();
      assertFalse(realms.isEmpty());
      assertTrue(realms.stream().anyMatch(r -> "master".equals(r.getRealm())));
    }
  }

  @Test
  void shouldCreateReadAndUpdateUserInTemporaryRealm() {
    String realmName = "itest-" + UUID.randomUUID().toString().substring(0, 8);
    String username = "user-" + UUID.randomUUID().toString().substring(0, 8);

    try (Keycloak client = newAdminClient()) {
      RealmRepresentation realm = new RealmRepresentation();
      realm.setRealm(realmName);
      realm.setEnabled(true);
      client.realms().create(realm);

      try {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(true);
        user.setFirstName("Initial");
        user.setLastName("Name");
        user.setEmail(username + "@example.com");

        String userId;
        try (Response createResponse = client.realm(realmName).users().create(user)) {
          userId = CreatedResponseUtil.getCreatedId(createResponse);
        }

        assertNotNull(userId);

        UserRepresentation existing =
            client.realm(realmName).users().get(userId).toRepresentation();
        assertEquals("Initial", existing.getFirstName());

        existing.setFirstName("Updated");
        client.realm(realmName).users().get(userId).update(existing);

        UserRepresentation updated = client.realm(realmName).users().get(userId).toRepresentation();
        assertEquals("Updated", updated.getFirstName());
      } finally {
        client.realm(realmName).remove();
      }
    }
  }
}
