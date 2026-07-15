#!/usr/bin/env bash
# Build, sign, and push the ACS edge-policy bundle (RFC-05 P0 — Provenance).
#
# Pipeline (this is what CI runs; it is the ONLY sanctioned way policy reaches
# the ACS — the running module pods never serve policy to the authorizer):
#
#   1. GENERATE  one <name>.cedar (RFC-05 P2: generated
#                Tier-1 edge Cedar) per module from its OpenAPI x-labs64-auth,
#                via the commons OpenApiAuthPreprocessor (the single source of
#                truth for the coarse edge layer). Cedar files are validated
#                against the shared commons schema when the `cedar` CLI is
#                installed (CI installs it; locally it is a hard gate too).
#   2. ASSEMBLE  modules/<name>.cedar + manifest.json into a bundle dir.
#   3. PUSH      the bundle dir as an OCI artifact (oras) to the registry.
#   4. SIGN      the pushed artifact by digest (cosign).
#   5. EMIT      the digest — the deployment pins the ACS to THIS digest.
#
# Usage:
#   build-bundle.sh --version <ver> [--registry host:port] [--repo policies/labs64io]
#                   [--sources bundle-sources.yaml] [--sign] [--push]
#
# Env for signing (keyless is preferred in CI via OIDC; local uses a key pair):
#   COSIGN_KEY   path to a cosign private key (local/dev). If unset and --sign is
#                given, a dev key pair is generated under ./.cosign (gitignored).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=""
REGISTRY="${BUNDLE_REGISTRY:-localhost:5005}"
REPO="${BUNDLE_REPO:-policies/labs64io}"
SOURCES="$SCRIPT_DIR/bundle-sources.yaml"
DO_SIGN=false
DO_PUSH=false
COMMONS_DIR="${COMMONS_DIR:-$SCRIPT_DIR/../../labs64.io-commons/auth-context-java}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)  VERSION="$2"; shift 2;;
    --registry) REGISTRY="$2"; shift 2;;
    --repo)     REPO="$2"; shift 2;;
    --sources)  SOURCES="$2"; shift 2;;
    --sign)     DO_SIGN=true; shift;;
    --push)     DO_PUSH=true; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[[ -n "$VERSION" ]] || { echo "ERROR: --version is required" >&2; exit 2; }

BUILD_DIR="$SCRIPT_DIR/build"
BUNDLE_DIR="$BUILD_DIR/bundle"
rm -rf "$BUILD_DIR"; mkdir -p "$BUNDLE_DIR/modules"

# --- 0. commons preprocessor classpath (built jar + deps) -------------------
generate_policy() {  # <module> <openapi-in> <cedar-out>
  local module="$1" spec="$2" cedar_out="$3"
  local jar cp
  jar="$(ls "$COMMONS_DIR"/target/auth-context-*-*.jar 2>/dev/null | head -1 || true)"
  [[ -n "$jar" ]] || { echo "ERROR: commons jar not built ($COMMONS_DIR/target). Run 'mvn -pl auth-context-java package'." >&2; exit 1; }
  if [[ ! -f "$BUILD_DIR/cp.txt" ]]; then
    ( cd "$COMMONS_DIR" && mvn -q dependency:build-classpath -Dmdep.outputFile="$BUILD_DIR/cp.txt" )
  fi
  cp="$jar:$(cat "$BUILD_DIR/cp.txt")"
  java -cp "$cp" io.labs64.authcontext.openapi.OpenApiAuthPreprocessorCli \
    --input "$spec" --openapi-output "$BUILD_DIR/$(basename "$spec")" \
    --cedar-output "$cedar_out" --module "$module"
}

# Validate generated edge Cedar against the ONE shared schema (RFC-05 P5 "one
# schema, no drift"). Hard gate when the cedar CLI is available; loud warning
# otherwise (commons CI runs the same validation as a blocking job).
CEDAR_SCHEMA="$COMMONS_DIR/../auth-policy-cedar/schema.cedarschema"
validate_cedar() {  # <cedar-file>
  if command -v cedar >/dev/null; then
    cedar validate --schema "$CEDAR_SCHEMA" --schema-format cedar --policies "$1" >/dev/null \
      || { echo "ERROR: cedar validation failed for $1" >&2; exit 1; }
  else
    echo "WARN: cedar CLI not installed — skipping schema validation of $1" >&2
  fi
}

# --- 1 & 2. generate + assemble ---------------------------------------------
# Minimal YAML reader for the flat sources file (name/basePath/openapi triples).
python3 - "$SOURCES" "$BUNDLE_DIR" "$VERSION" "$SCRIPT_DIR" <<'PY' > "$BUILD_DIR/plan.txt"
import sys, yaml, os
sources, bundle_dir, version, script_dir = sys.argv[1:5]
cfg = yaml.safe_load(open(sources))
for m in cfg["modules"]:
    spec = m["openapi"]
    spec = spec if os.path.isabs(spec) else os.path.normpath(os.path.join(script_dir, spec))
    print(f'{m["name"]}\t{m["basePath"]}\t{spec}')
PY

MANIFEST_MODULES=""
while IFS=$'\t' read -r name base_path spec; do
  [[ -n "$name" ]] || continue
  echo "== generating $name from $spec"
  [[ -f "$spec" ]] || { echo "ERROR: OpenAPI spec not found: $spec" >&2; exit 1; }
  generate_policy "$name" "$spec" "$BUNDLE_DIR/modules/$name.cedar"
  validate_cedar "$BUNDLE_DIR/modules/$name.cedar"
  MANIFEST_MODULES="$MANIFEST_MODULES{\"name\":\"$name\",\"basePath\":\"$base_path\",\"cedar\":\"modules/$name.cedar\"},"
done < "$BUILD_DIR/plan.txt"

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"version":1,"bundleVersion":"%s","generatedAt":"%s","modules":[%s]}\n' \
  "$VERSION" "$GENERATED_AT" "${MANIFEST_MODULES%,}" \
  | python3 -m json.tool > "$BUNDLE_DIR/manifest.json"

echo "== bundle assembled at $BUNDLE_DIR"
ls -R "$BUNDLE_DIR"

REF="$REGISTRY/$REPO:$VERSION"

# --- 3. push ----------------------------------------------------------------
if $DO_PUSH; then
  command -v oras >/dev/null || { echo "ERROR: oras not installed" >&2; exit 1; }
  echo "== pushing $REF"
  ( cd "$BUNDLE_DIR" && oras push --plain-http "$REF" \
      --artifact-type application/vnd.labs64.authpolicy.bundle.v1 \
      manifest.json modules/ )
  DIGEST="$(oras resolve --plain-http "$REF")"
  echo "$DIGEST" > "$BUILD_DIR/digest.txt"
  echo "== pushed digest: $DIGEST"

  # --- 4. sign (by digest) --------------------------------------------------
  if $DO_SIGN; then
    command -v cosign >/dev/null || { echo "ERROR: cosign not installed" >&2; exit 1; }
    if [[ -z "${COSIGN_KEY:-}" ]]; then
      mkdir -p "$SCRIPT_DIR/.cosign"
      if [[ ! -f "$SCRIPT_DIR/.cosign/cosign.key" ]]; then
        echo "== generating dev cosign key pair (.cosign/, gitignored)"
        COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$SCRIPT_DIR/.cosign/cosign" >/dev/null
      fi
      COSIGN_KEY="$SCRIPT_DIR/.cosign/cosign.key"
    fi
    echo "== signing $REGISTRY/$REPO@$DIGEST"
    # cosign 3.x: local key-based signing with no transparency log needs a
    # signing-config whose rekor tlog services are removed (committed alongside).
    COSIGN_PASSWORD="" cosign sign --yes --allow-http-registry \
      --signing-config "$SCRIPT_DIR/signing-config.no-tlog.json" \
      --key "$COSIGN_KEY" "$REGISTRY/$REPO@$DIGEST"
    echo "== signed (verify: cosign verify --key <pub> --insecure-ignore-tlog --allow-http-registry $REGISTRY/$REPO@$DIGEST)"
  fi
fi

echo "BUNDLE_REF=$REF"
[[ -f "$BUILD_DIR/digest.txt" ]] && echo "BUNDLE_DIGEST=$(cat "$BUILD_DIR/digest.txt")"
