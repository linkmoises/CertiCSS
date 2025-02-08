#!/bin/bash
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
COMMIT_HASH=$(git rev-parse --short HEAD)
VERSION="${BRANCH_NAME}-${COMMIT_HASH}"
echo "$VERSION" > version.txt
echo "Versión generada: $VERSION"