package io.phasetwo.keycloak.admin;

/** Shared setup for the integration tests. */
final class TestKeycloak {

  /**
   * The Keycloak container image the integration tests run against.
   *
   * <p>Driven by the {@code keycloak-version} system property, which {@code pom.xml} wires to
   * {@code ${keycloak.version}} in the failsafe execution -- the same version this project compiles
   * and tests against. Pinning the container separately lets the two drift, and a drift between the
   * server we test on and the {@code keycloak-core} we build against is exactly the gap that would
   * hide a real incompatibility.
   *
   * <p>The default only applies when the property is absent, which in practice means running a test
   * directly from an IDE. Keep it equal to {@code keycloak.version} in {@code pom.xml}.
   */
  static final String IMAGE =
      String.format(
          "quay.io/keycloak/keycloak:%s", System.getProperty("keycloak-version", "26.6.1"));

  private TestKeycloak() {}
}
