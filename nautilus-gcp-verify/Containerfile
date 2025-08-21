# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# This containerfile uses StageX (https://stagex.tools) images, which provide a
# full source bootstrapped, deterministic, and hermetic build toolchain

FROM stagex/core-binutils@sha256:83c66e9d7393d7004442f8c1f2ad0f69979cc2a9193222338f4736abf17b6752 AS core-binutils
FROM stagex/core-ca-certificates@sha256:d6fca6c0080e8e5360cd85fc1c4bd3eab71ce626f40602e38488bfd61fd3e89d AS core-ca-certificates
FROM stagex/core-gcc@sha256:125bd6306e7f37e57d377d5a189c0e499388aff42b22cc79acee6097357c617f AS core-gcc
FROM stagex/core-git@sha256:5b0ce8741532026bb7e6f2302855a93057a27a7f38e596e9a7fb0e782f04d0f6 AS core-git
FROM stagex/core-zlib@sha256:b35b643642153b1620093cfe2963f5fa8e4d194fb2344a5786da5717018976c2 AS core-zlib
FROM stagex/core-llvm@sha256:bc1c6d67aa73a96dd92f5def7e2701de78b0639d0c815d69110fbb9b3b3e85fe AS core-llvm
FROM stagex/core-openssl@sha256:8670a22fb76965f31bda1b61cd75ae39a96e1008deffe289a5d94ee4337b1cb2 AS core-openssl
FROM stagex/core-rust@sha256:9be04ac253dabe11367336d29a1582a25535876a1b68fb9508ac85e898d812fd AS core-rust
FROM stagex/core-musl@sha256:d5f86324920cfc7fc34f0163502784b73161543ba0a312030a3ddff3ef8ab2f8 AS core-musl
FROM stagex/core-libunwind@sha256:4f3ead61255c1e58e7dc43a33043f297f8730ec88e068a4460e5fff09e503781 AS core-libunwind
FROM stagex/core-pkgconf@sha256:fb69c51519edd6aa8e889877b48d2b6874bc5756f72d412908dc629842c46b4a AS core-pkgconf
FROM stagex/core-busybox@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374 AS core-busybox
FROM stagex/core-python:local@sha256:17d634028c3ed31707aa492dc65dc15ac27bab197d08e447786b3b1e8c26df2c AS core-python
FROM stagex/core-libzstd@sha256:35ae8f0433cf1472f8fb25e74dc631723e9f458ca3e9544976beb724690adea8 AS core-libzstd
FROM stagex/user-eif_build@sha256:c1d030fcaa20d26cd144ce992ba4b77665a0e9683f01a92960f9823d39401e41 AS user-eif_build
FROM stagex/user-gen_initramfs@sha256:6c398be1eea26dcee005d11b5c063e1f7cf079710175e5d550d859c685d81825 AS user-gen_initramfs
FROM stagex/linux-nitro@sha256:073c4603686e3bdc0ed6755fee3203f6f6f1512e0ded09eaea8866b002b04264 AS user-linux-nitro
FROM stagex/user-cpio@sha256:2695e1b42f93ec3ea0545e270f0fda4adca3cb48d0526da01954efae1bce95c4 AS user-cpio
FROM stagex/user-socat:local@sha256:acef3dacc5b805d0eaaae0c2d13f567bf168620aea98c8d3e60ea5fd4e8c3108 AS user-socat
FROM stagex/user-jq@sha256:ced6213c21b570dde1077ef49966b64cbf83890859eff83f33c82620520b563e AS user-jq

FROM scratch as base
ENV TARGET=x86_64-unknown-linux-musl
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV CARGOFLAGS="--locked --no-default-features --release --target ${TARGET}"
ENV OPENSSL_STATIC=true

COPY --from=core-busybox . /
COPY --from=core-musl . /
COPY --from=core-libunwind . /
COPY --from=core-openssl . /
COPY --from=core-zlib . /
COPY --from=core-ca-certificates . /
COPY --from=core-libzstd . /
COPY --from=core-binutils . /
COPY --from=core-pkgconf . /
COPY --from=core-git . /
COPY --from=core-rust . /
COPY --from=user-gen_initramfs . /
COPY --from=user-eif_build . /
COPY --from=core-llvm . /
COPY --from=core-gcc . /
COPY --from=user-cpio . /
COPY --from=user-linux-nitro /bzImage .
COPY --from=user-linux-nitro /nsm.ko .
COPY --from=user-linux-nitro /linux.config .

FROM base as build
COPY . .

RUN cargo build --workspace --locked --no-default-features --release --target x86_64-unknown-linux-musl

WORKDIR /src/nautilus-server
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"
RUN cargo build --locked --no-default-features --release --target x86_64-unknown-linux-musl

WORKDIR /build_cpio
ENV KBUILD_BUILD_TIMESTAMP=1
RUN mkdir initramfs/
COPY --from=user-linux-nitro /nsm.ko initramfs/nsm.ko
COPY --from=core-busybox . initramfs
COPY --from=core-python . initramfs
COPY --from=core-musl . initramfs
COPY --from=core-ca-certificates /etc/ssl/certs initramfs
COPY --from=core-busybox /bin/sh initramfs/sh
COPY --from=user-jq /bin/jq initramfs
COPY --from=user-socat /bin/socat . initramfs
RUN cp /target/${TARGET}/release/init initramfs
RUN cp /src/nautilus-server/target/${TARGET}/release/nautilus-server initramfs
RUN cp /src/nautilus-server/traffic_forwarder.py initramfs/
RUN cp /src/nautilus-server/run.sh initramfs/
RUN cp /src/nautilus-server/allowed_endpoints.yaml initramfs/

RUN <<-EOF
    set -eux
    cd initramfs
    find . -exec touch -hcd "@0" "{}" +
    find . -print0 \
    | sort -z \
    | cpio \
        --null \
        --create \
        --verbose \
        --reproducible \
        --format=newc \
    | gzip --best \
    > /build_cpio/rootfs.cpio
EOF

WORKDIR /build_eif
RUN eif_build \
	--kernel /bzImage \
	--kernel_config /linux.config \
	--ramdisk /build_cpio/rootfs.cpio \
	--pcrs_output /nitro.pcrs \
	--output /nitro.eif \
	--cmdline 'reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd'

FROM base as install
WORKDIR /rootfs
COPY --from=build /nitro.eif .
COPY --from=build /nitro.pcrs .
COPY --from=build /build_cpio/rootfs.cpio .

FROM scratch as package
COPY --from=install /rootfs .

