#!/usr/bin/env bash
set -e

export GHIDRA_INSTALL_DIR=$HOME/build/ghidra_11.4.1_PUBLIC
export JAVA_HOME=/opt/homebrew/opt/openjdk@24

./gradlew
rm -rf $HOME/Library/ghidra/ghidra_11.4.1_PUBLIC/Extensions/SuperMonkeyBallTools/
unzip dist/ghidra_11.4.1_* -d $HOME/Library/ghidra/ghidra_11.4.1_PUBLIC/Extensions/
