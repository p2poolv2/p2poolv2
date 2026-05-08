#!/usr/bin/env bash
set -euo pipefail

SRC_TAG="ghcr.io/${GITHUB_REPOSITORY}:${IMAGE_SHA}"
ANN_SOURCE="org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}"
ANN_DESC="org.opencontainers.image.description=P2Poolv2 is a peer-to-peer Bitcoin mining pool where miners coordinate directly and verify their rewards without centralized operators."

docker buildx imagetools create \
  $(echo "${TAGS_GHCR}" | xargs -I{} echo -t {}) \
  --annotation "${ANN_SOURCE}" \
  --annotation "${ANN_DESC}" \
  "${SRC_TAG}-amd64" \
  "${SRC_TAG}-arm64" \
  "${SRC_TAG}-armv7"

docker buildx imagetools create \
  $(echo "${TAGS_DH}" | xargs -I{} echo -t {}) \
  --annotation "${ANN_SOURCE}" \
  --annotation "${ANN_DESC}" \
  "${SRC_TAG}"
