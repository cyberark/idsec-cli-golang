#!/bin/bash

# Create local idsec directory if it doesn't exist
mkdir -p ~/.idsec

# Run the idsec container with volume mapping
# Set consistent hostname so keyring encryption works across runs
docker run -it --rm \
  --hostname idsec-cli \
  -v "${HOME}/.idsec:/idsec" \
  cyberark/idsec-sdk-golang:dev "$@"
