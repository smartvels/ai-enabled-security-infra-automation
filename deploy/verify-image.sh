#!/usr/bin/env bash
# Deployment gate: refuse to deploy any triage image that is not signed by
# this repository's CI workflow on main, or that lacks its SBOM attestation.
#
# Usage:  ./verify-image.sh ghcr.io/<owner>/triage-service@sha256:<digest>
# Then:   TRIAGE_IMAGE=<same ref> docker compose up -d --no-build
#
# Requires: cosign (https://docs.sigstore.dev).
set -euo pipefail

REF="${1:?usage: $0 <image@sha256:digest>}"
OWNER_REPO="${OWNER_REPO:-smartvels/ai-enabled-security-infra-automation}"
SIGNER="https://github.com/${OWNER_REPO}/.github/workflows/security-and-tests.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"

# Only immutable digests are accepted; tags can be repointed by an attacker
if [[ "$REF" != *@sha256:* ]]; then
  echo "REJECTED: reference must be pinned by digest (image@sha256:...)" >&2
  exit 1
fi

echo "Verifying signature..."
cosign verify "$REF" --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" > /dev/null

echo "Verifying SBOM attestation..."
cosign verify-attestation "$REF" --type cyclonedx \
  --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" > /dev/null

echo "Verifying SLSA build provenance..."
cosign verify-attestation "$REF" --type slsaprovenance1 \
  --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" > /dev/null

echo "VERIFIED: $REF"
echo "Deploy with:  TRIAGE_IMAGE='$REF' docker compose up -d --no-build"
