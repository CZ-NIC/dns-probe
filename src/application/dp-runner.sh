#!/bin/sh

selfpath=$(
    selfpath=${0}
    while [ -L "${selfpath}" ]
    do
        cd "${selfpath%/*}" || exit
        selfpath=$(readlink "${selfpath}")
    done
    cd "${selfpath%/*}" || exit
    echo "$(pwd -P)"
)

while true
do
    "$selfpath"/dns-probe-@BACKEND@ "$@"
    if [ "$?" != '1' ]; then
        break
    fi
done
