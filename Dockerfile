ARG TOOLS_IMAGE=docker.horse/ci/on-alpine/tools:1

FROM $TOOLS_IMAGE AS tools

FROM docker.io/library/golang:1.26-alpine AS build

WORKDIR /usr/src/app/gltgr

ARG MIRROR_ALPINE_URL=""

ARG MIRROR_ALPINE_FALLBACK_URL=""

ARG MIRROR_GO_URL=""

COPY --from=tools /usr/local/bin/pkg-base-setup /usr/local/bin/

RUN pkg-base-setup && \
    apk add --no-cache git

COPY go.mod go.sum ./

RUN if [ -n "$MIRROR_GO_URL" ]; then go env -w GOPROXY="${MIRROR_GO_URL%/}|https://proxy.golang.org,direct"; fi

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -a -o gltgr . && \
    chmod +x gltgr

FROM docker.io/library/alpine:3

ARG MIRROR_ALPINE_URL=""

ARG MIRROR_ALPINE_FALLBACK_URL=""

COPY --from=tools /usr/local/bin/pkg-base-setup /usr/local/bin/

RUN pkg-base-setup

COPY --from=build /usr/src/app/gltgr/gltgr /usr/bin/gltgr

ENTRYPOINT ["/usr/bin/gltgr"]
