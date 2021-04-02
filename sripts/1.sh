#!/bin/bash
csv_file=$1
shift
pattern="$1"
if [ $# -gt 1 ]; then
    shift
    for i in "$@"; do
        pattern="$pattern\|$i"
    done
fi



grep  "^\($pattern\)" $csv_file

