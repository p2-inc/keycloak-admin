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

### 3. Get a `RealmRepresentation`

```java
import org.keycloak.representations.idm.RealmRepresentation;

RealmRepresentation realm = keycloak.realm("my-realm").toRepresentation();
System.out.println("Realm: " + realm.getRealm());
```

### 4. Get and update a user

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

### 5. Close the client

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

Run all tests:

```bash
mvn test
```

Run only the Keycloak Testcontainers integration test:

```bash
mvn -Dtest=KeycloakContainerIT test
```

### Test requirements

- The integration test (`KeycloakContainerIT`) uses `testcontainers-keycloak`.
- Docker must be running and available on the host.
