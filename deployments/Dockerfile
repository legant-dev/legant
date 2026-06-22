FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/legant ./cmd/legant

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/legant /usr/local/bin/legant

# Run as a non-root uid so the image is compatible with a hardened
# securityContext (runAsNonRoot). The binary needs no write access.
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["legant"]
CMD ["serve"]
