#!/bin/sh

sh -c "echo $*"
echo "Hello"
date
pwd
ls
uname -a
GODEBUG=asyncpreemptoff=1 go test -v ./math/...
date
