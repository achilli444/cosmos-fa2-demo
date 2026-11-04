#!/bin/sh
set -e

# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
    set -- traefik "$@"
fi

# if our command is a valid Traefik subcommand, let's invoke it through Traefik instead
# (this allows for "docker run traefik version", etc)
if traefik "$1" --help >/dev/null 2>&1
then
    set -- traefik "$@"
else
    echo "= '$1' is not a Traefik command: assuming shell execution." 1>&2
fi

umask 0077

# Traefik loads its install (static) configuration from a single source, so
# environment variables are ignored once /etc/traefik/traefik.yaml exists and
# the file itself is not templated. Render the service credential that the
# HTTP provider must send to /openc3-api/traefik into a copy of the config
# and boot from that copy. The file provider keeps reading the original file.
CONFIG=/etc/traefik/traefik.yaml
RENDERED=/tmp/traefik.yaml
# Only when traefik is started with no extra options (the default CMD above
# normalizes to "traefik traefik") so an explicit --configFile is never overridden.
render=true
for arg in "$@"; do
    [ "$arg" = "traefik" ] || render=false
done
if [ "$render" = "true" ] && [ -f "$CONFIG" ]; then
    if [ -z "$OPENC3_SERVICE_PASSWORD" ]; then
        echo "= OPENC3_SERVICE_PASSWORD is not set: /openc3-api/traefik polling will be rejected (401)" 1>&2
    elif awk -v placeholder='${OPENC3_SERVICE_PASSWORD}' '
        BEGIN { value = ENVIRON["OPENC3_SERVICE_PASSWORD"]; gsub(/\047/, "\047\047", value) }
        {
            line = $0
            out = ""
            while ((i = index(line, placeholder)) > 0) {
                out = out substr(line, 1, i - 1) value
                line = substr(line, i + length(placeholder))
            }
            print out line
        }' "$CONFIG" > "$RENDERED"; then
        set -- traefik --configFile="$RENDERED"
    else
        echo "= Could not write $RENDERED: running with unrendered $CONFIG" 1>&2
    fi
fi

exec "$@"
