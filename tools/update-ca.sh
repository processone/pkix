#!/bin/sh
##################################################################
#
#  Usage:
#  - clone the repo:
#    $ git clone git@github.com:processone/pkix.git
#  - run the script:
#    $ pkix/tools/update-ca.sh
#
#  NOTES; You absolutely need to run the script from cloned repo
#         and have write access to its remote
#
##################################################################

SCRIPT_DIR=$(dirname -z $0)
GIT_ROOT=$(git -C $SCRIPT_DIR rev-parse --show-toplevel)
CAFILE=$GIT_ROOT/priv/cacert.pem

curl --time-cond $CAFILE --output $CAFILE https://download.process-one.net/cacert.pem
CHANGES=$(git -C $GIT_ROOT diff --name-only $CAFILE)
if [ ! -z "$CHANGES" ]; then
    git -C $GIT_ROOT add $CAFILE
    git -C $GIT_ROOT commit -m "Update CA bundle"
    git -C $GIT_ROOT push
fi
