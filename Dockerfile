# One image for the whole stack: patchlog serve, index, tree, janitor, ….
#
# Multi-arch: the build stage runs on the builder's own platform and
# cross-compiles (the binary is pure Go), so an arm64 image doesn't compile
# under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/patchlog ./cmd/patchlog

FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/middle-management/patchlog" \
      org.opencontainers.image.description="Patch Log: versioned JSON documents as hash-chained patch logs"
RUN adduser -D -u 10001 patchlog && mkdir /data && chown patchlog /data
COPY --from=build /out/patchlog /usr/local/bin/patchlog
USER patchlog
WORKDIR /data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["patchlog"]
