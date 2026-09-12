# keycloak-admin

The goal of this library is to create a Keycloak Admin Client library that is not dependent on the Resteasy JAX-RS implementations, and just uses a simple wrapper on the Apache HttpClient and Jackson libraries.

## Implementation

- Implements an alternative to the org.keycloak.admin.client.Keycloak and KeycloakBuilder classes that does not use JAX-RS or Resteasy
- The TokenManager and TokenService are also reimplemented not to use JAX-RS or Resteasy.
- Uses the io.phasetwo.keycloak.admin.Http wraper to make a concrete implementation of all interfaces in the org.keycloak.admin.client.resource package.
- All dependencies are declared as `optional` in case you are using this from within Keycloak (our use case).

## Usage

### 1. Build a client with `client_credentials`

```java
import io.phasetwo.keycloak.admin.Keycloak;
import io.phasetwo.keycloak.admin.KeycloakBuilder;
import org.keycloak.OAuth2Constants;

Keycloak keycloak =
    KeycloakBuilder.builder()
        .serverUrl("https://sso.example.com")
        .realm("master")
        .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
        .clientId("admin-cli")
        .clientSecret("my-client-secret")
        .build();
```

### 2. Build a client with `password` grant

```java
import io.phasetwo.keycloak.admin.Keycloak;
import io.phasetwo.keycloak.admin.KeycloakBuilder;
import org.keycloak.OAuth2Constants;

Keycloak keycloak =
    KeycloakBuilder.builder()
        .serverUrl("https://sso.example.com")
        .realm("master")
        .grantType(OAuth2Constants.PASSWORD)
        .username("admin")
        .password("admin-password")
        .clientId("admin-cli")
        .build();
```

### 3. Build a client with `private_key_jwt` (RFC 7523)

Instead of a client secret, the client can authenticate with a JWT assertion signed by its private
key. The Keycloak client must have its authenticator set to `client-jwt` and the matching public key
configured, either inline (`use.jwks.string` / `jwks.string`) or by URL (`use.jwks.url` /
`jwks.url`).

```java
import io.phasetwo.keycloak.admin.Keycloak;
import io.phasetwo.keycloak.admin.KeycloakBuilder;
import io.phasetwo.keycloak.admin.PrivateKeyJwt;
import org.keycloak.OAuth2Constants;

Keycloak keycloak =
    KeycloakBuilder.builder()
        .serverUrl("https://sso.example.com")
        .realm("my-realm")
        .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
        .clientId("my-client")
        .clientAssertion(PrivateKeyJwt.withPem(privateKeyPem).keyId("my-key-1"))
        .build();
```

A fresh assertion is minted for every token request, addressed to the realm issuer URL and valid for
60 seconds by default. Both are configurable -- see `PrivateKeyJwt`.

To sign somewhere the key cannot be exported from, such as an HSM or a cloud KMS, implement
`ClientAssertionProvider` directly rather than using `PrivateKeyJwt`:

```java
import io.phasetwo.keycloak.admin.ClientAssertionProvider;

ClientAssertionProvider kms = context -> myKmsClient.signJwt(context.clientId(), context.realmIssuerUrl());
```

### 4. Get a `RealmRepresentation`

```java
import org.keycloak.representations.idm.RealmRepresentation;

RealmRepresentation realm = keycloak.realm("my-realm").toRepresentation();
System.out.println("Realm: " + realm.getRealm());
```

### 5. Get and update a user

```java
import java.util.List;
import org.keycloak.representations.idm.UserRepresentation;

List<UserRepresentation> users = keycloak.realm("my-realm").users().search("alice");
if (!users.isEmpty()) {
  UserRepresentation user = users.get(0);
  String userId = user.getId();

  UserRepresentation fullUser = keycloak.realm("my-realm").users().get(userId).toRepresentation();
  fullUser.setFirstName("Alice Updated");

  keycloak.realm("my-realm").users().get(userId).update(fullUser);
}
```

### 6. Close the client

```java
keycloak.close();
```

## Build and Test

### Build

Compile the project:

```bash
mvn clean compile
```

Build the jar:

```bash
mvn clean package
```

### Run tests

The tests are integration tests, named `*IT` and run by failsafe, so they run under `verify` rather
than `test`:

```bash
mvn verify
```

Run a single integration test:

```bash
mvn verify -Dit.test=KeycloakContainerIT
```

### Test requirements

- The integration tests use `testcontainers-keycloak`.
- Docker must be running and available on the host.
