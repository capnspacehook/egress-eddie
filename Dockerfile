FROM golang:1.20.0-alpine AS builder

COPY . /build
WORKDIR /build/cmd/egress-eddie

# add git so VCS info will be stamped in binary
RUN apk add --no-cache git=2.36.3-r0

# build as PIE to take advantage of exploit mitigations
ARG CGO_ENABLED=0
ARG VERSION
RUN go build -buildmode pie -buildvcs=true -ldflags "-s -w -X main.version=${VERSION}" -trimpath -o egress-eddie

# pie-loader is built and scanned daily, we want the most recent version
# hadolint ignore=DL3007
FROM ghcr.io/capnspacehook/pie-loader:latest
COPY --from=builder /build/cmd/egress-eddie/egress-eddie /egress-eddie

# apparently giving capabilities to containers doesn't work when the
# container isn't running as root inside the container, see
# https://github.com/moby/moby/issues/8460

ENTRYPOINT [ "/egress-eddie" ]
