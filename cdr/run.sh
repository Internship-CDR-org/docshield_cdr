#!/usr/bin/env bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: ./run.sh <input-file> <output-file>"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

mvn -q compile dependency:build-classpath \
    -Dmdep.outputFile=/tmp/docshield-classpath.txt

CLASSPATH="target/classes:$(cat /tmp/docshield-classpath.txt)"

java -cp "$CLASSPATH" Main "$INPUT" "$OUTPUT"
