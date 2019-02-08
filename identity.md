# Transparent Mutual Identity in the Virtual Private Mesh

In distributed, dynamically-scheduled microservice environments, it can be
very hard to know "who" is on either end of a connection. In order to answer
this question, we introduce an _Identity system_ that describes workloads
within the service mesh. This identity system is bound to cryptographic keys,
so that linkerd proxies can communicate confidentially, with mutually-
validated identities.

This is an important foundational step towards exposing _authorization
policies_ that describe how services are able to interact. However, aset of
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

### Installation

#### Configuration

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


#### Deployment

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

### Proxy Injection

Proxy injection will need to be modified to access the control plane's trust
anchor. The proxy-injector pod likely just mounts the anchors file.

Additionally, a Volume must be added to Linkerd-injected pods:

```yaml
volumes:
- name: linkerd-identity-store
  emptyDir:
    medium: Memory
```

This volume must be mounted into (only) the proxy container (under
`/var/run/linkerd/identity`)

The `LINKERD2_PROXY_POD_NAMESPACE` and `LINKERD2_PROXY_TLS_*` environment
variables are no longer set. Instead, injection sets the following environment variables:

- `LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS` -- a base64-encoded blob containing
  the control plane's trust anchors. This is inlined into the proxy configuration so that the
- `LINKERD2_PROXY_IDENTITY_STORE_PATH` -- the path under which the
  `linkerd-identity-store` volume is mounted.
- `LINKERD2_PROXY_IDENTITY_TOKEN_PATH` -- the path under which the
  authentication token may be read. For now, this will always be
  `/var/run/secrets/kubernetes.io/serviceaccount`; though, later, when it's
  possible to request narrower tokens (i.e. via the' `TokenRequestProjection`
  feature), we may specify other locations.
- `LINKERD2_PROXY_IDENTITY_DOMAIN` -- a domain suffix under which the pod's
   identity will be namespaced. A typical value would be
   `sa.linkerd.linkerd-identity.cluster.local` (when the control namespace
   is _linkerd_ and the trust domain is _cluster.local_).

### Destination Service


### Service Accounts & Identity

Previously, linkerd's `tls=optional` mode associated pod identity with,
effectively, a Kubernetes Deployment by publishing Secrets
(containing key material) that would be mounted into the appropriate pod.
However, any pod in deployment _mal_ can access deployment _bob_'s keys if
they share a service account. Service accounts are as good as Kubernetes can
give you, for now at least.

Linkerd identities are encoded as DNS-like names:

    UID . SERVICEACCOUNT . NAMESPACE .sa. CONTROLLER_NS .linkerd-identity. TRUST_DOMAIN...

For example:

    2c345c34-241f-11e9-bd44-80fa5b5b38db.testsa.default.linkerd.linkerd-identity.cluster.local

These names are intended to unambiguously identify a service account within a
linkerd controller's trust domain, and are not intended to be user-facing
(except for the purposes of validation and debugging). They should fit into
CA schemes, i.e. such that a signing authority (like the Identity service)

#### The Linkerd Identity Service

This change introduces a new gRPC service into linkerd2-proxy-api (though it
will *not* be served via the proxy-api Service, so that the Identity
service's privileges may be constrained appropriately).

The Identity service holds a signing key and certificate. As it receives
requests from proxies, it forwards the `token` onto the Kubernetes
`TokenReview` API to validate the service account. If the service account is
valid and the `certificate_signing_request` includes a `CommonName` with the
correct linkerd identity (as described above), it uses its signing key to
produce a short-lived certificate to the proxy.

The proxy can then use this certificate to prove its identity for both client
and server communications until the certificate expires.

At 80% of the certificate's lifetime (or, at least once per day), the proxy
renews its certificate from the identity service. It preemptively

##### Known Issue: Token Reuse

In the current proposal, each pod sends its service account to the Identity
service as proof of identity. A malicious Identity service could use this as
way to harvest service account tokens.

The proxy must validate the identity service's identity (when not
communicating over localhost) to ensure that it's sending the token to a
trusted endpoint.

Later, when the `BoundServiceAccountTokenVolume` feature is enabled in
Kubernetes, we should be able to obtain rotating tokens with a narrower
audience to further limit this exposure.


## The life of a Pod

### Inject

When a pod is injected (i.e. by Linkerd's inject controller), the injector
modifies the pod spec, as it did before, to add the container to pods. When
TLS is not explicitly disabled for the pod, it also does the following:

1. Add the controller's trust roots to the proxy pod and configure the
   proxy's environment appropriately.
2. Configure the proxy container with a tmpfs volume to the pod, to be used
   by the proxy to store key material in memory, though accessible for
   diagnostics during the pod's lifetime.
3. Configure the proxy with the hostname and id of the linkerd
   proxy-api service.
4. Configure the proxy with the hostname and id of the linkerd identity service.
   The identity service's identity is discovered via the discovery service.

### Startup

As the proxy container starts, instead of invoking the proxy directly, an
initialization script is run. This script runs a program that reads a service
account token, generates a private key and CSR corresponding to the identity
stored in the token, writing the results to tmpfs, and finally outputting the
linkerd identity name, which the init script uses to configure the proxy as
it execs it.

As the proxy starts, it initiates a secure connection to the proxy-api,
validating the proxy-api's identity with the configured trust root and id.
Additionally, the proxy establishes a secure connection to the identity
service, validated with the root and configured id. A timer task in the proxy obtains new

The proxy immediately begins serving inbound traffic, but does not terminate
TLS until a certificate has been acquired.

The proxy also immediately begins serving outbound traffic, using the
proxy-api to determine when TLS should be used with a peer and how the peer's
id should be validated. When the outbound proxy does not communicate with the
destination service to resolve a name (i.e. falling back to DNS)

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


### Questions

1. What should the proxy do with previously established connections when a certificate rotates?
2. How should the trust roots be injected to proxies?
  * config maps proliferated to each namespace/service-account?
    * if names are random, garbage collection problem
    * if names are stable, updates at random deploy-time? (maybe ok)?
  * base64-encoded env variable decoded by the init process?

## Installing a Linkerd control plane

