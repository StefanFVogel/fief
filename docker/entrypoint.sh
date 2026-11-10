#!/bin/sh
# Runs the container command as the unprivileged fief user (UID/GID 1000).
# Started as root, it first hands /data over to fief, so existing root-owned
# volumes keep working. Started as another user (e.g. Kubernetes runAsUser),
# it runs the command directly.
set -eu

if [ "$(id -u)" = "0" ]; then
  find /data ! -user fief -exec chown -h fief:fief {} + \
    || echo "entrypoint: could not hand /data over to fief" >&2
  # supervisord reopens /dev/stdout for the program logs; like with
  # `docker run --user`, the container's stdout/stderr must belong to fief.
  chown fief:fief /proc/self/fd/1 /proc/self/fd/2 2>/dev/null || true
  export HOME=/app
  exec setpriv --reuid=fief --regid=fief --init-groups "$@"
fi

exec "$@"
