# Transparent Mutual Identity in the Virtual Private Mesh

In distributed, dynamically-scheduled microservice environments, it can be
very hard to know "who" is on either end of a connection. In order to answer
this question, we introduce an _Identity system_ that describes workloads
within the service mesh. This identity system is bound to cryptographic keys,
so that linkerd proxies can communicate confidentially, with mutually-
validated identities.

This is an important foundational step towards exposing _authorization
policies_ that describe how services are able to interact. However, a set of
header-oriented utilities will be exposed so that applications can begin to
implement auditing and authorization based on linkerd-specific headers.

## Goals

1. Automatically establish private sessions between
   linkerd-meshed pods using mTLS with minimal operator overhead.
2. Bootstrap trust & identity from Kubernetes primitives.
3. Wherever possible, prevent private key material from touching disk.
4. Expose opt-in identity information and controls to applications via HTTP headers.
5. The Linkerd controller should not need role bindings to access secrets in
   application namespaces.

### Non-goals

* Participate in TLS with arbitrary clients/servers.
* Provide identity for non-HTTP traffic.
* Provide generalized CA infrastructure.

## Overview

* The `--tls` flag---and all associated logic, including the `linkerd-ca`
  controller---is completely removed from control plane installation and proxy inject.
* A new controller service, `linkerd-identity`, is introduced into the default
  linkerd installation. This service exposes a gRPC certification API.
  Proxies use this API to obtain a validated TLS certificate from an API
  token and Certificate Signing Request.
* The proxy container generates ephemeral private keys, stored in memory within
  the pod. This enables multiple pods to share a logical identity without
  sharing key material, limiting the impact of an exfiltrated key.

## Installation

### Configuration

A `linkerd-identity` service account must exist in the control plane namespace.

When the linkerd control plane is installed for the first time, the identity
service must be configured with some critical information:

* _Trust anchors_ -- A set of PEM-encoded root certificates that are used to
  validate identity certificates.
* A _Signing Key_ -- A DER-encoded private key to used to issue identity
  certificates. This key must not be password-protected.
* A _Signing Certificate_ -- An intermediate certificate that can be validated
  against the trust anchors.

A `linkerd-trust-anchor` ConfigMap is created in the controller namespace
containing the trust anchors file. This ConfigMap must be readable by the
Injector controller and by the user who deploys control plane pods.

A `linkerd-identity-signing` Secret is created in the controller namespace
containing the key and certificate. This Secret must ONLY be readable by the
linkerd-identity service account (i.e. and not the entire control plane
namespace). If the user does not have existing trust/signing infrastructure,
we should generate them during installation.

Additionally, the user may configure the following.

* A _trust domain_. In many configurations, this correspond to the cluster's
  configured DNS suffix (.e.g. `cluster.local`), though this is not a hard
  requirement and this trust domain need not be part of a real DNS domain.
  All identities issued in this mesh must be a subdomain of this trust
  domain.
* An _identity certificate lifetime_, indicating the amount of time for which
  the Identity services certifies identities. Initially, the default value
  should be 1 day.


### Deployment

When deploying the control plane (pods), a new `linkerd-identity` deployment
is added, using the `linkerd-identity` service account. Control plane
injection works the same as proxy injection (described below), with one
important exception: Proxies in `linkerd-identity` pods are configured
slightly differently: instead of communicating through the mesh to reach the
`linkerd-identity` service, the proxy simply accesses the service over
`localhost`. This is necessary so that the service can bootstrap its own
identity.

The `linkerd-proxy-api` deployment/service/etc should be renamed to the
`linkerd-destination` service, since the proxy-api suite of services is now
(rightly) split across networked services with separate privileges.

## Controllers

The destination, identity, and proxy injector controllers must share logic
for mapping between service accounts and identities:

- the proxy injector configures the proxy with its identity
- the destination service determines the identity for each pod
- the identity service validates kubernetes UserInfo against a CSR containing
  the injector-determined identity.

### Proxy Injection

When a proxy is being injected into a resource, we inspect resources for an
annotation, `linkerd.io/identity`, which may (currently) have one of two
values: _enabled_ or _disabled_. When no value is set, the cluster's default
configuration is used. When the value is set to _disabled_, all of the
following identity configuration is skipped. When the value is set to
_enabled_ and the control plane does not support identity, then injection
fails.

The `linkerd.io/identity` annotation may only be enabled on pod resources and
not on, for instances, Service resources. Injection should fail when a
non-pod-resource has identity enabled.

In any case, as the proxy is injected, the `linkerd.io/identity` annotation
is set to _enabled_ when the proxy is configured to participate with identity
and _disabled_ if identity is disabled.

When identity is not disabled, the following configuration is applied:

The `LINKERD2_PROXY_POD_NAMESPACE` and `LINKERD2_PROXY_TLS_*` environment
variables are no longer set. Instead, injection sets the following environment variables:

- `LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS_BLOB` -- a base64-encoded blob containing
  the control plane's trust anchors. This is inlined into the proxy configuration so that the
- `LINKERD2_PROXY_IDENTITY_STORE_DIR` -- the path under which the ephemeral
   identity store volume is mounted. See below.
- `LINKERD2_PROXY_IDENTITY_TOKEN_FILE` -- the path under which the
  (service account) authentication token may be read. For now, this will
  always be `/var/run/secrets/kubernetes.io/serviceaccount`; though, later,
  when it's possible to request narrower tokens (i.e. via the'
  `TokenRequestProjection` feature), we may specify other locations.
- `LINKERD2_PROXY_LOCAL_IDENTITY` -- A DNS-like name that identifies the
  workload within the mesh.
- `LINKERD2_PROXY_DESTINATION_ADDR` -- e.g.
  `linkerd-destination.linkerd.svc.cluster.local`
- `LINKERD2_PROXY_DESTINATION_IDENTITY` -- e.g.
  `linkerd-controller.linkerd.sa.linkerd-identity.linkerd.cluster.local`
- `LINKERD2_PROXY_IDENTITY_ADDR` -- e.g.
  `linkerd-identity.linkerd.svc.cluster.local`
- `LINKERD2_PROXY_IDENTITY_IDENTITY` -- e.g.
  `linkerd-identity.linkerd.sa.linkerd-identity.linkerd.cluster.local`

#### Identity Store Volume

A Volume must be added to Linkerd-injected pods:

```yaml
volumes:
- name: linkerd-identity-store
  emptyDir:
    medium: Memory
```

This volume must be mounted into (only) the proxy container (under
`/var/run/linkerd/identity`).

### Destination Service

The proxy will stop making local decisions about whether to establish TLS
with a remote peer, instead relying on the destination service to make this
decision. The destination service

*Note*: The proxy-api's destination service should drop it's k8s-specific
*references to, instead, simply passing back the identity name (perhaps
*`strategy: Mesh`).

### Identity Service

This change introduces a new gRPC service into linkerd2's proxy-api, though it
will *not* be served via the proxy-api Service, so that the Identity
service's privileges may be constrained appropriately.

The Identity service holds a signing key and certificate. As it receives
requests from proxies, it forwards the `token` onto the Kubernetes
`TokenReview` API to validate the service account. If the service account is
valid and the `certificate_signing_request` includes (only) a `DNSName` with
the correct linkerd identity (as described above), it uses its signing key to
produce a short-lived certificate to the proxy.

The proxy can then use this certificate to prove its identity for both client
and server communications until the certificate expires.

## Proxy

As the proxy container starts, instead of invoking the proxy directly, an
initialization script is run to, if identity is configured, generate a key so
that a certificate can be provisioned from the identity service.

If the `LINKERD2_PROXY_LOCAL_IDENTITY_NAME` is set, the
`LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS_BLOB` must be set to valid PEM-encoded set of
certificates, `LINKERD2_PROXY_IDENTITY_TOKEN_FILE` must be set to a readable
file, and `LINKERD2_PROXY_IDENTITY_STORE_DIR` must be set to a writeable
directory. Otherwise, the script should fail to start the proxy before keys
are generated.

### Key Generation

If `LINKERD2_PROXY_LOCAL_IDENTITY_NAME` is set, a DER-encoded ECDSA private key is
generated into a file in `${LINKERD2_PROXY_IDENTITY_STORE_DIR}/key.der` with
the permissions 0400---this key will not change throughout the life of the
process.

A DER-encoded Certificate Signing Request (CSR) containing only one DNSName
SAN, which is set from `LINKERD2_PROXY_LOCAL_IDENTITY_NAME`, is generated and stored in
`$[LINKERD2_PROXY_IDENTITY_STORE_DIR}/csr.p8` with permissions 0400---this,
too, will not change throughout the life of the process.

Furthermore, the `LINKERD_PROXY_TRUST_ANCHORS_BLOB` value is base64-decoded,
parsed to validate that it contains valid PEM-encoded certificates, and
stored to `$[LINKERD2_PROXY_IDENTITY_STORE_DIR}/trust-anchors.pem`, again at
0400 to indicate that this file is not updated at runtime.

The `LINKERD2_PROXY_IDENTITY_KEY_FILE`, `LINKERD2_PROXY_IDENTITY_CSR_FILE`,
and `LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS_FILE` environment variables are
set to each of these generated files so that the proxy can discover them as it starts.

### Certification

As the proxy starts, it reads `LINKERD2_PROXY_LOCAL_IDENTITY_NAME`, loads the
private key in `LINKERD2_PROXY_IDENTITY_KEY_FILE`, the CSR in
`LINKERD2_PROXY_IDENTITY_CSR_FILE`, and the trust anchors from
`LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS_FILE`.

The proxy immediately begins serving inbound traffic. When a connection is
accepted and TLS is detected, it is checked for an SNI value matching
`LINKERD2_PROXY_LOCAL_IDENTITY_NAME`. Until the proxy has acquired a
certificate for this identity, these connections are refused (and not
forwarded or otherwise decoded).

The proxy creates a client to the destination service at
`LINKERD2_PROXY_DESTINATION_ADDR`. If the addr refers to a loopback address,
then the `LINKERD2_PROXY_DESTINATION_IDENTITY` variable must not be set; and,
otherwise, if the addr is not a loopback address and the proxy is configured
with identity trust anchors, then the identity _must_ be set so that the
client can establish a private connection to the destination service using
the trust anchors (even though the proxy may not yet have an
identity certificate).

The proxy immediately begins routing outbound traffic using the
destination service client (or DNS) for discovery. When the destination
service provides an identity for endpoints (as described above), then the
proxy uses its trust anchor to establish private connections to these
endpoints. When the proxy has a valid certificate of its own, then
it does provides client authentication; otherwise, client authentication may
be omitted on outbound connections.

Finally (though, in practice, concurrently), it creates a client to
`LINKERD2_PROXY_IDENTITY_ADDR`. If the addr refers to a loopback address,
then the `LINKERD2_PROXY_IDENTITY_IDENTITY` variable must not be set; and,
otherwise, if the addr is not a loopback address, then the identity _must_ be
set so that the client can establish a private connection to the identity
service using the trust anchors (even though the proxy doesn't yet have an
identity certificate).

The proxy immediately issues a `Certify` request to the identity service,
loading the contents of `LINKERD2_PROXY_IDENTITY_TOKEN_FILE` (so that the
value may update on each request), and including the contents of
`LINKERD2_PROXY_IDENTITY_CSR_FILE` (which need only be loaded once at
startup).

The proxy's admin endpoint exposes a readiness check endpoint that, when
identity is configured, fails until the proxy has provisioned a certificate.

#### When the proxy can't obtain a new certificate from the identity service

If the Identity service is failing, or if the proxy's container loses access
to its service account token, or if the service account is deleted from the
kubernetes API server so that the account token is no longer valid, or if
there is another failure that prevents the proxy from refreshing its
certificates from the identity service, then the proxy's certificate may
expire.

When the proxy's certificate expires, the proxy refuses new inbound TLS'd
connections and it stops providing client authentication on outbound TLS'd
connections.

The proxy's admin endpoint should expose a liveness check endpoint that
fails when the proxy is configured with an identity but its certificate has
expired.

## Appendix

### Questions

1. What should the proxy do with previously established connections when a certificate rotates?
2. To UID or not?

### When a Pod is compromised

In the case that a pod becomes compromised, we aim to limit the potential
exposure by (1) using unique, ephemeral keys in each proxy pod, and (2)
rotating certificates from the identity service frequently. However,
especially due to the service account token issue described above, the best
course of action is delete the Service Account and its resources.

This prevents the attacker from using the account's token to provision
additional certificates from the Identity service. This, coupled with short
certificate lifetimes, avoids the needs for complicated certificate
revocation schemes.

However, at this point, a new account may be created with the same name and
applications would be unable to distinguish the identity of the two accounts.
We compensate for this by including Kubernetes' unique UID in the identity
string in each certificate, e.g.:

    2c345c34-241f-11e9-bd44-80fa5b5b38db.testsa.default.linkerd.linkerd-identity.cluster.local
    44fbcb79-241f-11e9-bd44-80fa5b5b38db.testsa.default.linkerd.linkerd-identity.cluster.local

#### Token Reuse

In the current proposal, each pod sends its service account to the Identity
service as proof of identity. A malicious Identity service could use this as
way to harvest service account tokens.

The proxy must validate the identity service's identity (when not
communicating over localhost) to ensure that it's sending the token to a
trusted endpoint.

Later, when the `BoundServiceAccountTokenVolume` feature is enabled in
Kubernetes, we should be able to obtain rotating tokens with a narrower
audience to further limit this exposure.


### Determining the proxy's identity with the Kubernetes downward API

```yaml
env:
  - name: L5D_NS
    value: linkerd
  - name: TRUST_DOMAIN
    value: cluster.local
  - name: K8S_SA
    valueFrom: {fieldRef: {fieldPath: spec.serviceAccountName}}
  - name: K8S_NS
    valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
  - name: LINKERD2_PROXY_LOCAL_IDENTITY_NAME
    value: $(K8S_SA).$(K8S_NS).sa.linkerd-identity.$(L5D_NS).$(TRUST_DOMAIN)
```
