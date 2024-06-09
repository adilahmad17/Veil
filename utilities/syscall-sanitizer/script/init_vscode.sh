#!/bin/bash
# Refer to git contrib/vscode/init.sh

die () {
        echo "$*" >&2
        exit 1
}

CUR_DIR=$(readlink -f $(dirname $BASH_SOURCE))
source $CUR_DIR/env.sh

cd $CUR_DIR/../ 
mkdir -p .vscode
# General settings
echo 
cat <<EOF >.vscode/settings.json
{
        "go.goroot": "$DEP/go",
        "go.gopath": "$DEP/gopath",
                "terminal.integrated.env.linux": {
                "PATH": "$DEP/go/bin:$PATH"
        },
}
EOF