FROM docker.io/library/golang:1.26-alpine AS build

WORKDIR /usr/src/app/gltgr

RUN sed --in-place 's!https://dl-cdn.alpinelinux.org/alpine!https://linux.sex/dl-cdn.alpinelinux.org!g' /etc/apk/repositories || true && \
    apk --verbose update && \
    apk --verbose upgrade --available && \
    apk add git ca-certificates tzdata && \
    update-ca-certificates && \
    apk cache clean

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -a -o gltgr . && \
    chmod +x gltgr

FROM docker.io/library/alpine:3

RUN sed --in-place 's!https://dl-cdn.alpinelinux.org/alpine!https://linux.sex/dl-cdn.alpinelinux.org!g' /etc/apk/repositories || true && \
    apk --verbose update && \
    apk --verbose upgrade --available && \
    apk add ca-certificates tzdata && \
    update-ca-certificates && \
    apk cache clean

COPY --from=build /usr/src/app/gltgr/gltgr /usr/bin/gltgr

ENTRYPOINT ["/usr/bin/gltgr"]
