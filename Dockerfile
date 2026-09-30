# One image for the whole stack: patchlog serve, index, tree, janitor, ….
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/patchlog ./cmd/patchlog

FROM alpine:3.22
RUN adduser -D -u 10001 patchlog && mkdir /data && chown patchlog /data
COPY --from=build /out/patchlog /usr/local/bin/patchlog
USER patchlog
WORKDIR /data
VOLUME /data
ENTRYPOINT ["patchlog"]
