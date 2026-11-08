#!/bin/sh
# Blocks a release if the fief CLI can't start in the given image: without a
# lockfile, a floating dependency can break it at any image build.
# The values are the dummy ones from .github/actions/test/action.yml.
set -eu

image=$1

docker run --rm "$image" pip freeze --all

for args in "--help" "run-server --help" "run-worker --help"; do
  echo "fief $args"
  docker run --rm \
    -e ENVIRONMENT=development \
    -e SECRET=ThisShouldBeChangedInProduction \
    -e ENCRYPTION_KEY=uSieBJ_695D2NA7bOPUJqFGCS2_qI8G4aI6L42WhjjM= \
    -e DATABASE_TYPE=SQLITE \
    -e DATABASE_NAME=fief \
    -e FIEF_CLIENT_ID=FIEF_CLIENT_ID \
    -e FIEF_CLIENT_SECRET=FIEF_CLIENT_SECRET \
    "$image" fief $args >/dev/null
done

echo "Smoke test passed: $image"
