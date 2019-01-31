# Transparent Mutual Identity in the Virtual Private Mesh

## Goals

1. Automatically establish private sessions between
   linkerd-meshed pods using mTLS with minimal operator overhead.
2. Bootstrap trust & identity from Kubernetes primitives.
3. Wherever possible, prevent private key material from touching disk.
4. Expose opt-in identity information and controls to applications via HTTP headers.

## Overview

This document proposes a plan for the following:

1. `--tls=optional` is removed. Identity is provided by default and may be
   disabled by `--disable-control-plane-identity` and inject-time
   configurations to opt-out of identity for applications.
   By default, when two meshed pods are communicating over HTTP,
   linkerd proxies will require validated TLS identity.
2. linkerd-ca's Secret distribution scheme (which incurs unnecessary RBAC
   with linkerd-identity's online certificate provisioning scheme. The proxy
   container is responsible for generating its own private key, storing it in
   memory, and obtaining (and refreshing) certificates from the (new)
   linkerd-identity control plane service to be used for TLS termination.
3. Linkerd's Identity is bound to Kubernetes Service Accounts, and trust is
   bootstrapped on the secure distribution of Kubernetes service account
   tokens and Secrets.

### Service Accounts & Identity

Previously, linkerd's `tls=optional` mode associated pod identity with,
effectively, a Kubernetes Deployment by publishing Secrets
(containing key material) that would be mounted into the appropriate pod.
However, any pod in deployment _mal_ can access deployment _bob_'s keys if
they share a service account. Service accounts are as good as Kubernetes can
give you, for now at least.

Linkerd identities are encoded as DNS-like names:

    UID . SERVICEACCOUNT . NAMESPACE . CONTROLLER_NS .sa.linkerd-identity. TRUST_DOMAIN...

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
3. Configure the proxy with the hostname and identity of the linkerd
   proxy-api service.
4. Configure the proxy with the hostname of the linkerd identity service.
   The identity service's identity is discovered via the discovery service.

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

