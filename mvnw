#!/bin/sh
# Maven Wrapper script (POSIX shell)
set -e
exec "$(dirname "$0")/.mvn/wrapper/MavenWrapperDownloader.sh" "$@" 2>/dev/null || \
  exec mvn "$@"
