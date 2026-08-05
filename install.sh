#!/usr/bin/env bash
set -euo pipefail
trap 's=$?; echo >&2 "$0: Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR

GHIDRA_VERSION=12.0.1
JDK_VERSION=21

export GHIDRA_INSTALL_DIR=$HOME/build/ghidra_${GHIDRA_VERSION}_PUBLIC
export JAVA_HOME=/opt/homebrew/opt/openjdk@${JDK_VERSION}
GHIDRA_USER_DIR=$HOME/Library/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC

rm -rf dist
./gradlew
rm -rf $GHIDRA_USER_DIR/Extensions/SuperMonkeyBallTools/
rm -rf $GHIDRA_INSTALL_DIR/Extensions/SuperMonkeyBallTools/
unzip dist/ghidra_${GHIDRA_VERSION}_* -d $GHIDRA_USER_DIR/Extensions

