#!/bin/sh
set -e

repo=$1
pin=$2

head=$(git -C "$repo" rev-parse HEAD)
pinrev=$(git -C "$repo" rev-parse "$pin")
origin=$(git -C "$repo" config --get remote.origin.url)


if [ -z "$DONT_PIN" ]; then
    if [ ! -f /git-metadata.csv ]; then
        echo "pin,pinrev,origin,path" > /git-metadata.csv
    fi
    echo "$pin,$pinrev,$origin,$repo" >> /git-metadata.csv

    echo "Pinning $repo to $pin (from: $head)"
    git -C "$repo" checkout --quiet "$pin"
    git -C "$repo" submodule update;
else
    if [ ! -f /git-metadata.csv ]; then
        echo "head,pin,pinrev,origin,path" > /git-metadata.csv
    fi
    echo "$head,$revision,$pinrev,$origin,$repo" >> /git-metadata.csv

    echo "Skipping $repo pin to $revision (from: $head)";
fi
