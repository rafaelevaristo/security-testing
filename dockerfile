FROM alpine:3.18

RUN apk add --no-cache \
    bash \
    curl \
    openssl \
    ca-certificates \
    grep \
    sed \
    coreutils

WORKDIR /app

# Copy scripts and configuration
COPY security_test.sh /app/
COPY config.conf /app/
COPY docker-entrypoint.sh /app/

# Copy project hosts file (required for build)
COPY hosts /etc/hosts

RUN chmod +x /app/security_test.sh /app/docker-entrypoint.sh
RUN mkdir -p /app/logs /app/reports

VOLUME ["/app/logs", "/app/reports"]

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["--help"]
