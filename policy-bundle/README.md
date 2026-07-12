# Edge-policy bundle (RFC-05 P0 — Provenance)

Provenance-safe distribution of the ACS edge auth policies. Instead of the
authproxy pulling each module's `/.well-known/auth-policy` live from the very pod
it authorizes (RFC-05 finding **F2** — self-authored runtime policy, a privilege
escalation path), CI generates the policies from the modules' OpenAPI
`x-labs64-auth` metadata, assembles a bundle, **cosign-signs** it, and pushes it
to an OCI registry. The ACS loads that bundle **by digest**, and an init
container **verifies the signature before the ACS starts**. The authorized pod
can no longer author the policy that governs it.

## Pipeline

```
OpenAPI x-labs64-auth ──(commons OpenApiAuthPreprocessor)──▶ modules/<name>.json
        │
        └─ manifest.json  ──(oras push)──▶ OCI registry ──(cosign sign, by digest)──▶ signed bundle
                                                                         │
   ACS init: oras pull @digest ──▶ cosign verify (fail-closed) ──▶ /bundle ──▶ policy_bundle.py
```

## Build, sign, push

```bash
# needs: java + mvn (commons jar built), oras, cosign
./build-bundle.sh --version 1.0.0 --push --sign
# → prints BUNDLE_REF and BUNDLE_DIGEST; dev signing key generated under .cosign/
```

`bundle-sources.yaml` declares each module's `name`, `basePath`, and OpenAPI
spec path. `signing-config.no-tlog.json` is a cosign 3.x signing config with the
transparency-log services removed (local key signing, no Rekor).

## Deploy the ACS in bundle mode

Enable `policyBundle` on the `traefik-authproxy` chart with the digest + public
key from the build:

```bash
DIGEST=$(cat policy-bundle/build/digest.txt)
PUB=$(cat policy-bundle/.cosign/cosign.pub)
helm upgrade labs64io-traefik-authproxy ./charts/traefik-authproxy -n labs64io \
  -f charts/traefik-authproxy/values.yaml \
  -f overrides/traefik-authproxy/values.local.yaml \
  -f overrides/traefik-authproxy/values.bundle.local.yaml \
  --set policyBundle.digest="$DIGEST" \
  --set-literal policyBundle.cosignPublicKey="$PUB"
```

In bundle mode the ACS logs `policy source: signed bundle (/bundle)` and never
starts the live Kubernetes discovery loop.

## Security properties

- **Content integrity** — pull is by immutable `sha256` digest; any tampering
  changes the digest and the pull fails.
- **Authenticity** — `cosign verify` against the pinned public key is a hard
  init-container gate; an unsigned or wrong-key bundle aborts pod startup
  (verified: a mismatched key is rejected with "Found: 0, Expected 1").
- **Fail closed** — a missing/broken bundle leaves the policy table empty
  (deny-all) and the ACS never reports ready (`policy_bundle.py`).

## Not yet done (later P0/P2 hardening)

- Keyless (OIDC) signing in real CI instead of a local key pair.
- SBOM attestation on the bundle artifact.
- Wiring the digest into GitOps so a new bundle is a reviewed, pinned bump
  (today the digest is passed at deploy time).
