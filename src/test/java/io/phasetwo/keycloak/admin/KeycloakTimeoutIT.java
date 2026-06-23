package io.phasetwo.keycloak.admin;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import eu.rekawek.toxiproxy.Proxy;
import eu.rekawek.toxiproxy.ToxiproxyClient;
import eu.rekawek.toxiproxy.model.ToxicDirection;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.Timeout;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.ToxiproxyContainer;

@TestInstance(Lifecycle.PER_CLASS)
class KeycloakTimeoutIT {

  private static final String KC_IMAGE = "quay.io/keycloak/keycloak:26.5.3";
  private static final String TOXI_IMAGE = "ghcr.io/shopify/toxiproxy:2.9.0";
  private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(10);
  private static final int PROXY_PORT = 8666;

  private Network network;
  private KeycloakContainer keycloak;
  private ToxiproxyContainer toxiproxy;
  private ToxiproxyClient toxiproxyClient;
  private Proxy proxy;
  private String proxyUrl;

  private static boolean hasCause(Throwable t, Class<? extends Throwable> type) {
    for (Throwable c = t; c != null; c = c.getCause()) {
      if (type.isInstance(c)) return true;
    }
    return false;
  }

  private static Throwable rootCause(Throwable t) {
    while (t.getCause() != null) t = t.getCause();
    return t;
  }

  @BeforeAll
  void startContainers() throws Exception {
    Assumptions.assumeTrue(
        DockerClientFactory.instance().isDockerAvailable(), "Docker is not available");

    network = Network.newNetwork();

    keycloak =
        new KeycloakContainer(KC_IMAGE)
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withNetwork(network)
            .withNetworkAliases("keycloak");
    keycloak.start();

    toxiproxy = new ToxiproxyContainer(TOXI_IMAGE).withNetwork(network);
    toxiproxy.addExposedPort(PROXY_PORT);
    toxiproxy.start();

    toxiproxyClient = new ToxiproxyClient(toxiproxy.getHost(), toxiproxy.getMappedPort(8474));
    proxy = toxiproxyClient.createProxy("kc-proxy", "0.0.0.0:" + PROXY_PORT, "keycloak:8080");

    proxyUrl = "http://" + toxiproxy.getHost() + ":" + toxiproxy.getMappedPort(PROXY_PORT);
  }

  @AfterAll
  void stopContainers() {
    if (toxiproxy != null) toxiproxy.stop();
    if (keycloak != null) keycloak.stop();
    if (network != null) network.close();
  }

  @Test
  void trafficFlowsThroughProxyWithNoToxic() {
    try (Keycloak client = adminClientViaProxy()) {
      List<RealmRepresentation> realms = client.realms().findAll();
      assertFalse(realms.isEmpty());
    }
  }

  @Test
  void socketTimeoutFiresWhenProxyHangsTraffic() throws Exception {
    var toxic = proxy.toxics().timeout("hang", ToxicDirection.DOWNSTREAM, 0);
    try {
      long startNs = System.nanoTime();
      IllegalStateException ex =
          assertThrows(
              IllegalStateException.class,
              () -> {
                assertTimeoutPreemptively(Duration.ofSeconds(90), () -> {
                  try (Keycloak client = adminClientViaProxy()) {
                    client.realms().findAll();
                  }
                });
              });
      long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

      assertTrue(
          elapsedMs < CLIENT_TIMEOUT.toMillis() * 3,
          "Expected timeout < " + (CLIENT_TIMEOUT.toMillis() * 3) + "ms, took " + elapsedMs + "ms");
      assertTrue(
          hasCause(ex, SocketTimeoutException.class),
          "Expected SocketTimeoutException in cause chain, got: " + rootCause(ex));
    } finally {
      toxic.remove();
    }
  }

  @Test
  void socketTimeoutFiresOnResourceProxyCallAfterTokenWarmed() throws Exception {
    try (Keycloak client = adminClientViaProxy()) {
      // Warm the token cache via TokenService → Http; proxy is healthy at this point.
      client.tokenManager().getAccessTokenString();

      // Delete and recreate the proxy to tear down the pooled TCP connection.
      // Without this, HttpClient reuses the existing socket and a freshly-added
      // latency toxic may not affect bytes already in flight on that connection.
      proxy.delete();
      proxy = toxiproxyClient.createProxy("kc-proxy", "0.0.0.0:" + PROXY_PORT, "keycloak:8080");

      // Token is cached; realms().findAll() won't call the token endpoint —
      // it opens a fresh connection through ResourceProxyFactory → Http → HttpClient,
      // hitting the latency toxic. The exception surfaces as UndeclaredThrowableException
      // (checked IOException from invokeHttp escaping through the JDK proxy) rather than
      // the IllegalStateException that TokenService wraps it in.
      var toxic = proxy.toxics().latency("hang-realms", ToxicDirection.DOWNSTREAM, 60_000);
      try {
        long startNs = System.nanoTime();
        RuntimeException ex =
            assertThrows(RuntimeException.class, () -> {
              assertTimeoutPreemptively(Duration.ofSeconds(90), () -> client.realms().findAll());
            });
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

        assertTrue(
            elapsedMs < CLIENT_TIMEOUT.toMillis() * 3,
            "Expected timeout < "
                + (CLIENT_TIMEOUT.toMillis() * 3)
                + "ms, took "
                + elapsedMs
                + "ms");
        assertTrue(
            hasCause(ex, SocketTimeoutException.class),
            "Expected SocketTimeoutException in cause chain, got: " + rootCause(ex));
      } finally {
        toxic.remove();
      }
    }
  }

  private Keycloak adminClientViaProxy() {
    return KeycloakBuilder.builder()
        .serverUrl(proxyUrl)
        .realm("master")
        .grantType(OAuth2Constants.PASSWORD)
        .username("admin")
        .password("admin")
        .timeout(CLIENT_TIMEOUT)
        .clientId("admin-cli")
        .build();
  }
}
