#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=cilium/hubble
hubble_version="v0.10.0"

declare -A hubble_sha256
# renovate: datasource=github-releases depName=cilium/hubble digestVersion=v0.10.0
hubble_sha256[amd64]="b421b7cfb8a616d8206fcf725a21a0e168b47e7009a74f4070d7e7cced8ccfad"
# renovate: datasource=github-releases depName=cilium/hubble digestVersion=v0.10.0
hubble_sha256[arm64]="dd7dd0dab8c2234517a4f3b3ad1c65d1675f24dfafc6520b513fd088388a284c"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/cilium/hubble/releases/download/${hubble_version}/hubble-linux-${arch}.tar.gz" --output "/tmp/hubble-${arch}.tgz"
  printf "%s %s" "${hubble_sha256[${arch}]}" "/tmp/hubble-${arch}.tgz" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  tar -C "/out/linux/${arch}/bin" -xf "/tmp/hubble-${arch}.tgz" hubble
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/hubble
aarch64-linux-gnu-strip /out/linux/arm64/bin/hubble
