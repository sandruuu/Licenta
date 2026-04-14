FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o cloud .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser
WORKDIR /app

RUN mkdir -p /app/config /app/data /app/certs /app/web /app/dashboard && \
    chown -R appuser:appuser /app

COPY --from=builder /build/cloud /app/cloud
COPY docker-config.json /app/config/cloud-config.json
COPY web /app/web
COPY dashboard/dist /app/dashboard/dist

USER appuser
EXPOSE 8443
VOLUME ["/app/data", "/app/certs"]

ENTRYPOINT ["./cloud"]
CMD ["--config", "/app/config/cloud-config.json"]
