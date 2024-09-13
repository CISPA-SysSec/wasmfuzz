#!/bin/bash
set -e

origin=$1
path=$2
pin=$3

echo "Cloning $origin at revision $pin"
if [[ $* == *--recursive* ]]; then
    # The hack below doesn't really work here so we stick to (filtered) clones
    git clone --filter=tree:0 "$origin" "$path" --recursive
    git -C "$path" checkout --quiet "$pin"
    git -C "$path" submodule update
else
    # https://stackoverflow.com/a/43136160
    mkdir -p "$path"
    git -C "$path" init --initial-branch=x --quiet
    git -C "$path" remote add origin $origin
    git -C "$path" fetch --depth 1 origin $pin
    git -C "$path" checkout --quiet FETCH_HEAD
fi

# origin=$(git -C "$path" config --get remote.origin.url)
pinrev=$(git -C "$path" rev-parse "$pin")

if [ ! -f /git-metadata.csv ]; then
    echo "pin,pinrev,origin,path" > /git-metadata.csv
fi
echo "$pin,$pinrev,$origin,$path" >> /git-metadata.csv
