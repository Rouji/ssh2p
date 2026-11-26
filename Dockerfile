ARG ALPINE_VERSION=3.24
ARG LIBSSH_VERSION=0.12.2
ARG CURL_VERSION=8.23.0

FROM alpine:${ALPINE_VERSION} AS build

ARG LIBSSH_VERSION
ARG CURL_VERSION

RUN apk add --no-cache \
    build-base \
    cmake \
    meson \
    ninja \
    pkgconf \
    perl \
    ca-certificates \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static

# libssh (static)
RUN set -eux; \
    cd /tmp; \
    wget -q "https://www.libssh.org/files/0.12/libssh-${LIBSSH_VERSION}.tar.xz"; \
    tar -xf "libssh-${LIBSSH_VERSION}.tar.xz"; \
    cd "libssh-${LIBSSH_VERSION}"; \
    mkdir build; cd build; \
    cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=OFF \
    -DWITH_STATIC_LIB=ON \
    -DWITH_SERVER=ON \
    -DWITH_ZLIB=ON \
    -DWITH_EXAMPLES=OFF \
    -DUNIT_TESTING=OFF; \
    cmake --build . -j "$(nproc)"; \
    cmake --install .; \
    rm -rf /tmp/libssh-*

# libcurl (static)
RUN set -eux; \
    cd /tmp; \
    wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.xz"; \
    tar -xf "curl-${CURL_VERSION}.tar.xz"; \
    cd "curl-${CURL_VERSION}"; \
    ./configure \
    --prefix=/usr/local \
    --disable-shared \
    --enable-static \
    --with-openssl \
    --with-zlib \
    --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
    --without-libpsl \
    --without-nghttp2 \
    --without-brotli \
    --without-zstd \
    --without-libidn2 \
    --without-librtmp \
    --without-libssh2 \
    --disable-ldap \
    --disable-ldaps; \
    make -j "$(nproc)"; \
    make install; \
    rm -rf /tmp/curl-*

WORKDIR /src
COPY . .

# Static build (uses libssh/libcurl from /usr/local above)
RUN set -eux; \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    meson setup build -Dstatic_build=true --buildtype=release; \
    ninja -C build; \
    strip build/ssh2p; \
    ./build/ssh2p 2>&1 | head -1 || true

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/build/ssh2p /ssh2p

EXPOSE 22
ENTRYPOINT ["/ssh2p"]
