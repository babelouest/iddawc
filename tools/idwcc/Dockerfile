FROM alpine:latest AS builder

ARG IDDAWC_VERSION
ARG ALPINE_VERSION

COPY iddawc-dev-full_${IDDAWC_VERSION}_alpine_${ALPINE_VERSION}_x86_64.tar.gz /opt/iddawc.tar.gz

# Install required packages
RUN apk add --no-cache \
    git \
    make \
    cmake \
    wget \
    gcc \
    libmicrohttpd \
    jansson \
    gnutls \
    wget \
    cmake && \
    cd /opt && \
    tar xf ./iddawc.tar.gz && \
    ls -l && \
    tar xf liborcania-dev_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libyder-dev_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libulfius-dev_*.tar.gz -C /usr/ --strip 1 && \
    tar xf librhonabwy-dev_*.tar.gz -C /usr/ --strip 1 && \
    tar xf libiddawc-dev_*.tar.gz -C /usr/ --strip 1


FROM alpine:latest AS runner
RUN apk add --no-cache \
    wget \
    sqlite \
    libconfig \
    jansson \
    gnutls \
    libcurl \
    libmicrohttpd \
    bash

COPY --from=builder /usr/lib/liborcania* /usr/lib/
COPY --from=builder /usr/lib/libyder* /usr/lib/
COPY --from=builder /usr/lib/libulfius* /usr/lib/
COPY --from=builder /usr/lib/librhonabwy* /usr/lib/
COPY --from=builder /usr/lib/libiddawc* /usr/lib/
COPY --from=builder /usr/bin/idwcc /usr/bin
COPY --from=builder /usr/share/idwcc/ /usr/share/idwcc/

COPY ["entrypoint.sh", "/"]

CMD ["/entrypoint.sh"]
