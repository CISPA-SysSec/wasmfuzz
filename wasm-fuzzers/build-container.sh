#!/usr/bin/env bash

if command -v podman >/dev/null 2>&1; then
    podman build --cache-ttl=72h $@
else
    docker build $@
fi