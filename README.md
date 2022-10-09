# SuperMonkeyBallTools for Ghidra
Utilities to help reverse engineer Super Monkey Ball 2 with [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

## Features
- Converting a Ghidra address to an address in GameCube memory
- Converting a Ghidra address to a location in a .dol/.rel file
- Converting an address in GameCube memory to a Ghidra address

This is accessible from `Window > SMB: Convert Address` in CodeBrowser

## Default keybinds
- **Shift-G**: Go to GameCube RAM address

## Building
- Ensure you have `JAVA_HOME` set to the path of your JDK installation
- Set `GHIDRA_INSTALL_DIR` to your Ghidra install directory. This can be done in one of the following ways:
    - **Windows**: Running `set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>`
    - **macOS/Linux**: Running `export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`
    - Using `-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>` when running `gradle`
    - Adding `GHIDRA_INSTALL_DIR` to your environment variables.
- Run `.\gradlew.bat` (Windows) or `./gradlew` (Linux)
- You'll find the output .zip file inside `/dist`

## Installation
- Copy the zip file to `<Ghidra install directory>/Extensions/Ghidra`
- Start Ghidra, go to (`File > Install Extensions...`), and enable the extension

