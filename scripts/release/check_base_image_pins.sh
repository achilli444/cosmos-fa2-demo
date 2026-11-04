#!/usr/bin/env bash
# Checks that the external base images at the root of the COSMOS image chain are
# pinned by digest and that the service Dockerfiles built on top of that chain
# (openc3, openc3-cosmos-cmd-tlm-api, openc3-cosmos-script-runner-api) cannot
# fall back to a mutable :latest base.
#
# Usage: scripts/release/check_base_image_pins.sh [--resolve]
#   --resolve  also resolve alpine:${ALPINE_VERSION}.${ALPINE_BUILD} from
#              ${OPENC3_DEPENDENCY_REGISTRY} and require its digest to equal
#              ALPINE_DIGEST (needs network + docker buildx).
set -u
cd "$(dirname -- "$0")/../.." || exit 1

RESOLVE=0
[[ "${1:-}" == "--resolve" ]] && RESOLVE=1

FAILED=0
fail() { echo "FAIL: $*" 1>&2; FAILED=1; }
pass() { echo "ok:   $*"; }

env_value() { sed -n "s/^$1=//p" .env | tail -n 1; }

ALPINE_VERSION="$(env_value ALPINE_VERSION)"
ALPINE_BUILD="$(env_value ALPINE_BUILD)"
ALPINE_DIGEST="$(env_value ALPINE_DIGEST)"
DEPENDENCY_REGISTRY="${OPENC3_DEPENDENCY_REGISTRY:-$(env_value OPENC3_DEPENDENCY_REGISTRY)}"

# 1. Root alpine image is pinned by digest and .env matches the Dockerfile default
if [[ "$ALPINE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  pass ".env ALPINE_DIGEST=$ALPINE_DIGEST"
else
  fail ".env ALPINE_DIGEST is missing or not a sha256 digest"
fi
DOCKERFILE_DIGEST="$(sed -n 's/^ARG ALPINE_DIGEST=//p' openc3-ruby/Dockerfile)"
if [[ -n "$ALPINE_DIGEST" && "$DOCKERFILE_DIGEST" == "$ALPINE_DIGEST" ]]; then
  pass "openc3-ruby/Dockerfile ARG ALPINE_DIGEST matches .env"
else
  fail "openc3-ruby/Dockerfile ARG ALPINE_DIGEST ('$DOCKERFILE_DIGEST') does not match .env ('$ALPINE_DIGEST')"
fi
if grep -Eq '^FROM \$\{OPENC3_DEPENDENCY_REGISTRY\}/alpine:\$\{ALPINE_VERSION\}\.\$\{ALPINE_BUILD\}@\$\{ALPINE_DIGEST\}$' openc3-ruby/Dockerfile; then
  pass "openc3-ruby/Dockerfile FROM alpine carries @\${ALPINE_DIGEST}"
else
  fail "openc3-ruby/Dockerfile FROM alpine is not digest-pinned"
fi
if grep -Eq '^FROM .*\$\{OPENC3_UBI_TAG\}\$\{OPENC3_UBI_DIGEST\}$' openc3-ruby/Dockerfile-ubi; then
  pass "openc3-ruby/Dockerfile-ubi FROM carries \${OPENC3_UBI_DIGEST}"
else
  fail "openc3-ruby/Dockerfile-ubi FROM has no digest build-arg"
fi
if grep -q 'ALPINE_DIGEST: ${ALPINE_DIGEST}' compose-build.yaml; then
  pass "compose-build.yaml passes ALPINE_DIGEST to openc3-ruby"
else
  fail "compose-build.yaml does not pass ALPINE_DIGEST to openc3-ruby"
fi
if [[ "$(grep -cF -- '--build-arg ALPINE_DIGEST=${ALPINE_DIGEST}' scripts/release/build_multi_arch.sh)" -ge 2 ]]; then
  pass "build_multi_arch.sh passes ALPINE_DIGEST for both openc3-ruby builds"
else
  fail "build_multi_arch.sh does not pass ALPINE_DIGEST for both openc3-ruby builds"
fi

# 2. Service Dockerfiles on the chain: no :latest default, digest slot present
for f in openc3/Dockerfile openc3-cosmos-cmd-tlm-api/Dockerfile openc3-cosmos-script-runner-api/Dockerfile; do
  if grep -Eq '^ARG OPENC3_TAG=' "$f"; then
    fail "$f gives OPENC3_TAG a default ($(grep -E '^ARG OPENC3_TAG=' "$f"))"
  else
    pass "$f has no OPENC3_TAG default"
  fi
  if grep -Eq '^FROM \$\{OPENC3_REGISTRY\}/\$\{OPENC3_NAMESPACE\}/\$\{OPENC3_IMAGE\}:\$\{OPENC3_TAG\}\$\{OPENC3_BASE_DIGEST\}$' "$f"; then
    pass "$f FROM accepts OPENC3_BASE_DIGEST"
  else
    fail "$f FROM does not accept OPENC3_BASE_DIGEST"
  fi
done

# 3. Optional: the pinned digest really is alpine:${ALPINE_VERSION}.${ALPINE_BUILD}
if [[ $RESOLVE -eq 1 ]]; then
  REF="${DEPENDENCY_REGISTRY}/alpine:${ALPINE_VERSION}.${ALPINE_BUILD}"
  [[ "$DEPENDENCY_REGISTRY" == "docker.io" ]] && REF="docker.io/library/alpine:${ALPINE_VERSION}.${ALPINE_BUILD}"
  RESOLVED="$(docker buildx imagetools inspect "$REF" 2>/dev/null | sed -n 's/^Digest: *//p' | head -n 1)"
  if [[ -z "$RESOLVED" ]]; then
    fail "could not resolve $REF (network/registry access?)"
  elif [[ "$RESOLVED" == "$ALPINE_DIGEST" ]]; then
    pass "$REF resolves to ALPINE_DIGEST"
  else
    fail "$REF resolves to $RESOLVED, but ALPINE_DIGEST=$ALPINE_DIGEST (update .env and openc3-ruby/Dockerfile together)"
  fi
fi

if [[ $FAILED -ne 0 ]]; then
  echo "check_base_image_pins: FAILED" 1>&2
  exit 1
fi
echo "check_base_image_pins: all checks passed"
