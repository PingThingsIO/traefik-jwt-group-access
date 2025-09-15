# traefik-jwt-group-access

Traefik middleware plugin which decodes a JWT token and checks that the JWT has an allowed group.

## Tested Traefik Versions

This pllugin has been tested on Traefik v3.4.3, and works with that version, it may not be compatible with older versions (it's written with go1.25 in mind).

## Installation

The plugin needs to be configured in the Traefik static configuration before it can be used.

### Installation on Kubernetes with Helm

The following snippet can be used as an example for the `values.yaml` file:

```values.yaml
experimental:
  plugins:
    enabled: true

additionalArguments:
- --experimental.plugins.traefik-jwt-group-access.modulename=github.com/PingThingsIO/traefik-jwt-group-access
- --experimental.plugins.traefik-jwt-group-access.version=v0.0.1
```

### Installation via command line

```shell
traefik \
  --experimental.plugins.traefik-jwt-group-access.moduleName=github.com/PingThingsIO/traefik-jwt-group-access \
  --experimental.plugins.traefik-jwt-group-access.version=v0.0.1
```

## Configuration

### Kubernetes

``` tab="File (Kubernetes)"
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: jwt-group-access
spec:
  plugin:
    traefik-jwt-group-access:
      claimsPrefix: attr
      allowGroups:
        - admin
        - test
      groupProperty: "groups"
```

## License

This software is released under the Apache 2.0 License
