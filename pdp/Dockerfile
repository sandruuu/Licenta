FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o pdp ./cmd/pdp

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser
WORKDIR /app

RUN mkdir -p /app/config /app/data /app/certs /app/dashboard && \
    chown -R appuser:appuser /app

COPY --from=builder /build/pdp /app/pdp
COPY docker-pdp-config.json /app/config/pdp-config.json
COPY pa/dashboard/dist /app/dashboard/dist

USER appuser
EXPOSE 8443
VOLUME ["/app/data", "/app/certs"]

ENTRYPOINT ["./pdp"]
CMD ["--config", "/app/config/pdp-config.json"]
