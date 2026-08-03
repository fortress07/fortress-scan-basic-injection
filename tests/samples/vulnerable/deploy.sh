#!/usr/bin/env bash
set -euo pipefail

TARGET="$1"
BRANCH=$2

read USER_INPUT

eval "git checkout $BRANCH"

rsync -a ./dist/ $TARGET

echo "deployed to $TARGET"
