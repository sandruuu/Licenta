FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /build/bin && CGO_ENABLED=0 go build -o /build/bin/pdp ./cmd/pdp

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser
WORKDIR /app

RUN mkdir -p /app/data /app/certs /app/dashboard && \
    chown -R appuser:appuser /app

COPY --from=builder /build/bin/pdp /app/pdp
COPY config.json /app/config.json
COPY pa/dashboard/dist /app/dashboard/dist

USER appuser
EXPOSE 8443
VOLUME ["/app/data", "/app/certs"]

ENTRYPOINT ["./pdp"]
