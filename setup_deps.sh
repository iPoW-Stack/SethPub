#!/bin/bash
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build xxd python3 openssl libssl-dev libgmp-dev flex bison lbzip2
echo DEPS_OK
