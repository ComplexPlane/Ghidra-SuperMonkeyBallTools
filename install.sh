#!/usr/bin/env bash
set -e

export GHIDRA_INSTALL_DIR=$HOME/build/ghidra_11.4.1_PUBLIC
export JAVA_HOME=/opt/homebrew/opt/openjdk@21
GHIDRA_USER_DIR=$HOME/Library/ghidra/ghidra_11.4.1_PUBLIC

rm -rf dist
./gradlew
rm -rf $GHIDRA_USER_DIR/Extensions/SuperMonkeyBallTools/
rm -rf $GHIDRA_INSTALL_DIR/Extensions/SuperMonkeyBallTools/
unzip dist/ghidra_11.4.1_* -d $GHIDRA_USER_DIR/Extensions

