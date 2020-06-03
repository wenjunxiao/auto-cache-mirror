#!/bin/bash
set -x
mkdir -p $GIT_ROOT
cd $GIT_ROOT
mkdir -p $GIT_USER
cd $GIT_USER
rm -rf $GIT_PROJECT.git
# git init --bare $GIT_PROJECT.git
# cd $GIT_PROJECT.git
if [ -z "$GIT_BIN" ]; then
  GIT_BIN="git"
fi
echo "git bin => $GIT_BIN"
GIT_URL=$GIT_BASE/$GIT_USER/$GIT_PROJECT.git
echo "git clone start => $GIT_URL"
GIT_SSL_NO_VERIFY=true $GIT_BIN clone --mirror $GIT_URL
# GIT_SSL_NO_VERIFY=true git push -u --all
echo "git clone done."