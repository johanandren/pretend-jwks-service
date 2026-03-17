# Dummy openid and jwt/jwks service

Use Maven to build your project:

```shell
mvn compile
```

To start your service locally, run:

```shell
mvn compile exec:java
```

You can use the [Akka Console](https://console.akka.io) to create a project and see the status of your service.

Build container image:

```shell
mvn clean install -DskipTests
```

Install the `akka` CLI as documented in [Install Akka CLI](https://doc.akka.io/reference/cli/index.html).

Deploy the service using the image tag from above `mvn install`:

```shell
akka service deploy pretend-jwks-service empty-service:tag-name --push
```

Needs to be deployed as a single node (generates keypair on boot) and exposed.

Exposed dns name must be set as env var PUBLIC_HOSTNAME

Example descriptor:

```yaml
name: pretend-jwks-service
service:
  env:
  - name: PUBLIC_HOSTNAME
    value: myservice.example.com
  image: myorg/pretend-jwks-service:1.0-SNAPSHOT
  resources:
    autoscaling:
      maxInstances: 1
      minInstances: 1
    runtime:
      mode: embedded
  workloadIdentity: {}
```

## API Endpoints

### Issue a JWT token

```shell
curl -X POST http://localhost:9000/auth \
  -H "Content-Type: application/json" \
  -d '{"subject": "my-user"}'
```

### Issue a JWT token for anonymous subject

```shell
curl -X POST http://localhost:9000/auth
```

### Rotate the signing key

```shell
curl -X POST http://localhost:9000/rotate
```

### Get JWKS (public keys)

```shell
curl http://localhost:9000/.well-known/jwks.json
```

### Get OpenID configuration

```shell
curl http://localhost:9000/.well-known/openid-configuration
```
