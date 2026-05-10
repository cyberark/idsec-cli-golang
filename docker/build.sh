#!/bin/bash
set -e

# Image name and tag
IMAGE_NAME=${IMAGE_NAME:-"cyberark/idsec-sdk-golang"}
IMAGE_TAG=${IMAGE_TAG:-"dev"}

echo "Building Docker image using project Makefile..."
echo "  IMAGE: $IMAGE_NAME:$IMAGE_TAG"
echo ""

# Build the Docker image (Makefile will handle all build metadata)
docker build \
  -f docker/Dockerfile \
  -t "$IMAGE_NAME:$IMAGE_TAG" \
  .

echo ""
echo "✅ Docker image built successfully: $IMAGE_NAME:$IMAGE_TAG"
echo ""
echo "To run the container:"
echo "  ./docker/idsec-cli.sh --help"
echo ""
echo "Or manually:"
echo "  docker run -it --rm -v \"\${HOME}/.idsec:/idsec\" $IMAGE_NAME:$IMAGE_TAG --help"
