# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# This containerfile uses StageX (https://stagex.tools) images, which provide a
# full source bootstrapped, deterministic, and hermetic build toolchain

FROM stagex/core-binutils@sha256:f2d3bf6104db0d5ac39ca155c0241bfea2516a6829e3b4fd657cf9ba5b625478 AS core-binutils
FROM stagex/core-ca-certificates@sha256:d135f1189e9b232eb7316626bf7858534c5540b2fc53dced80a4c9a95f26493e AS core-ca-certificates
FROM stagex/core-gcc@sha256:964ffd3793c5a38ca581e9faefd19918c259f1611c4cbf5dc8be612e3a8b72f5 AS core-gcc
FROM stagex/core-git@sha256:6b3e0055f6aeaa8465f207a871db2c63a939cd7406113e9d769ff3b37239f3d0 AS core-git
FROM stagex/core-zlib@sha256:06f5168e20d85d1eb1d19836cdf96addc069769b40f8f0f4a7a70b2f49fc18f8 AS core-zlib
FROM stagex/core-libffi@sha256:64d087343541401271cf9fec6b7bd788040c72a16918748ae36c171e53e94002 AS core-libffi
FROM stagex/core-llvm@sha256:583ecda677f51b69857f8027dfc58f4a931d1adc4d16214870a373505210d973 AS core-llvm
FROM stagex/core-openssl@sha256:d6487f0cb15f4ee02b420c717cb9abd85d73043c0bb3a2c6ce07688b23c1df07 AS core-openssl
FROM stagex/core-rust@sha256:2ea0be043b92321b5d1c2784911a770ccca28c09c3cf6a0f81fc0cd05a2abb08 AS core-rust
FROM stagex/core-musl@sha256:d9af23284cca2e1002cd53159ada469dfe6d6791814e72d6163c7de18d4ae701 AS core-musl
FROM stagex/core-libunwind@sha256:eb66122d8fc543f5e2f335bb1616f8c3a471604383e2c0a9df4a8e278505d3bc AS core-libunwind
FROM stagex/core-pkgconf@sha256:52624a89bb8cc684bc0391fcb7770ded2bbcb281e84bdb68a31fce127439fd7b AS core-pkgconf
FROM stagex/core-busybox@sha256:637b1e0d9866807fac94c22d6dc4b2e1f45c8a5ca1113c88172e0324a30c7283 AS core-busybox
FROM stagex/core-python@sha256:95504b36f4340782f5aa492d68f9a713406391898bf41cd62c9c9b54d6bee3f1 AS core-python
FROM stagex/core-libzstd@sha256:5382c221194b6d0690eb65ccca01c720a6bd39f92e610dbc0e99ba43f38f3094 AS core-libzstd
FROM stagex/user-eif_build@sha256:935032172a23772ea1a35c6334aa98aa7b0c46f9e34a040347c7b2a73496ef8a AS user-eif_build
FROM stagex/user-gen_initramfs@sha256:a87e9a3fa8468d2e08b5abb0a6da4c7a11df22273e2c526cb22e6b131151def8 AS user-gen_initramfs
FROM stagex/user-linux-nitro@sha256:aa1006d91a7265b33b86160031daad2fdf54ec2663ed5ccbd312567cc9beff2c AS user-linux-nitro
FROM stagex/user-cpio@sha256:9c8bf39001eca8a71d5617b46f8c9b4f7426db41a052f198d73400de6f8a16df AS user-cpio
FROM stagex/user-socat@sha256:4d1b7a403eba65087a3f69200d2644d01b63f0ea81ef171cedc17de490c8c9a0 AS user-socat
FROM stagex/user-jq@sha256:0c75672e97f54b83661aaa498e053340305e79cdc2004a40d92b7bf5ce906e9c AS user-jq
FROM stagex/user-nit@sha256:60b6eef4534ea6ea78d9f29e4c7feb27407b615424f20ad8943d807191688be7 AS user-nit

FROM scratch AS base
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
COPY --from=core-libffi . /
COPY --from=core-gcc . /
COPY --from=user-cpio . /
COPY --from=user-linux-nitro /bzImage .
COPY --from=user-linux-nitro /linux.config .

FROM base AS build
COPY . .

WORKDIR /src/nautilus-server
ENV OPENSSL_STATIC=true
ENV TARGET=x86_64-unknown-linux-musl
ARG ENCLAVE_APP
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"
RUN cargo build --locked --no-default-features --features $ENCLAVE_APP --release --target "$TARGET"

WORKDIR /build_cpio
ENV KBUILD_BUILD_TIMESTAMP=1
RUN mkdir initramfs/
# Built-in as of latest linux-nitro
# COPY --from=user-linux-nitro /nsm.ko initramfs/nsm.ko
COPY --from=core-busybox . initramfs
COPY --from=core-python . initramfs
COPY --from=core-musl . initramfs
COPY --from=core-ca-certificates /etc/ssl/certs initramfs
COPY --from=core-busybox /bin/sh initramfs/sh
COPY --from=user-jq /bin/jq initramfs
COPY --from=user-socat /bin/socat . initramfs
COPY --from=user-nit /bin/init initramfs
RUN cp /src/nautilus-server/target/${TARGET}/release/nautilus-server initramfs
RUN cp /src/nautilus-server/traffic_forwarder.py initramfs/
RUN cp /src/nautilus-server/run.sh initramfs/

COPY <<-EOF initramfs/etc/environment
SSL_CERT_FILE=/ca-certificates.crt
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/
EOF

RUN <<-EOF
    set -eux
    cd initramfs
    find . -exec touch -hcd "@0" "{}" + -print0 \
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
	--cmdline 'reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd nit.target=/run.sh'

FROM base AS install
WORKDIR /rootfs
COPY --from=build /nitro.eif .
COPY --from=build /nitro.pcrs .
COPY --from=build /build_cpio/rootfs.cpio .

FROM scratch AS package
COPY --from=install /rootfs .
