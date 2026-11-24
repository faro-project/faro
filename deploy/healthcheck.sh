#!/bin/bash
# Container health check for faro-server (used by the Dockerfile HEALTHCHECK).
#
# faro-server has no dedicated health endpoint, but GET /.well-known/faro is
# public, cheap, and is answered by the full router with the instance's
# identity loaded, so a 200 from it means "this instance is up and would
# answer a client". The script only needs bash (its /dev/tcp redirection),
# which the Debian runtime image already has, so no curl is installed.
#
# * Plain HTTP (behind a proxy or tunnel, or --dev): request
#   /.well-known/faro and require an HTTP 200 status line.
# * Built-in TLS (FARO_TLS_ACME_DOMAIN or FARO_TLS_CERT_PATH set): there is
#   no TLS client in the image, so only check that the port accepts TCP
#   connections.
#
# The port comes from FARO_LISTEN (the image sets 0.0.0.0:8080). If you
# configure the listen address in a faro.toml instead, keep FARO_LISTEN in
# step or override the health check in docker-compose.yml.

set -u

listen="${FARO_LISTEN:-0.0.0.0:8080}"
port="${listen##*:}"
case "$port" in
    '' | *[!0-9]*)
        echo "healthcheck: cannot read a port from FARO_LISTEN=$listen" >&2
        exit 1
        ;;
esac

# Every listen address faro-server accepts (0.0.0.0, [::] or 127.0.0.1)
# is reachable on loopback from inside the container.
if ! exec 3<>"/dev/tcp/127.0.0.1/$port"; then
    echo "healthcheck: nothing is listening on port $port" >&2
    exit 1
fi

if [ -n "${FARO_TLS_ACME_DOMAIN:-}${FARO_TLS_CERT_PATH:-}" ]; then
    exec 3>&-
    exit 0
fi

printf 'GET /.well-known/faro HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
status=""
IFS= read -r -t 5 status <&3
exec 3>&-
case "$status" in
    'HTTP/1.1 200'*) exit 0 ;;
esac
echo "healthcheck: unexpected response: ${status:-<none>}" >&2
exit 1
