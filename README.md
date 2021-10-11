# GTIRB Ghidra Plugin

This repo contains the source for building a Ghidra plugin to handle
GTIRB files.

Some limitations:
 - Imports GTIRB created from ELF files (only)
 - Supported architectures are IA32, ARM, X86-64, and PPC32
 - File name must have ".gtirb" suffix (otherwise you will have to
   manually select the GTIRB loader)
 - Builds are specific to a single version of Ghidra and will not work with
   newer or older Ghidra releases.

## Demonstration:

A video demonstration of installing and using this plugin is available at
   [gtirb-ghidra-plugin-intro.mov](https://grammatech.github.io/gtirb-ghidra-plugin/gtirb-ghidra-plugin-intro.mov).

## Build and Install

See the Installation section above to use the provided builds. To build from source instead:

The command-line examples in this section are for Ubuntu 20.04 and Ghidra 10.0.4, assuming you want to install Ghidra and Gradle to `~/.local`. Adjust them as appropriate to fit your system and Ghidra version.

1. Download the latest release of Ghidra [from Github](https://github.com/NationalSecurityAgency/ghidra/releases).
2. Download Gradle v5.1.1 from https://gradle.org/releases/
    * The latest versions of Gradle (v7.0+) do NOT work. Scroll down on the releases page for the older release.
3. Install OpenJDK 11
   ```sh
   sudo apt-get install openjdk-11-jdk
   ```
4. Extract Ghidra and Gradle somewhere convenient
   ```sh
   unzip -d ~/.local ~/Downloads/ghidra_10.0.4_PUBLIC_20210928.zip
   unzip -d ~/.local ~/Downloads/gradle-5.1.1-bin.zip
   ```
5. Add your Ghidra install path to a Gradle properties file
   ```sh
   mkdir -p ~/.gradle
   echo "GHIDRA_INSTALL_DIR=$HOME/.local/ghidra_10.0.4_PUBLIC" >> ~/.gradle/gradle.properties
   ```
6. Download or clone the gtirb-ghidra-plugin source.
   ```sh
   git clone https://github.com/GrammaTech/gtirb-ghidra-plugin.git
   cd gtirb-ghidra-plugin
   ```
7. Build [gtirb](https://github.com/GrammaTech/gtirb) from source for Java and install its `gtirb_api` and `protobuf-java` JAR files to `gtirb-ghidra-plugin/Gtirb/lib`. You can use the `gtirb_java_build.sh` script to automate this.
   ```sh
   ./scripts/gtirb_java_build.sh
   ```
8. Build the plugin with Gradle and extract it to `GHIDRA_INSTALL_DIR/Ghidra/Extensions`. You can use the `install_plugin.sh` script to automate this.
   ```sh
   ./scripts/install_plugin.sh
   ```

## Usage - GUI

Use Ghidra's `ghidraRun` script to launch the Ghidra project window.

To import a GTIRB file, simply open it from the "File -> Import File..." menu.
Ghidra should automatically use the installed GTIRB plugin to load it.

To export a program to GTIRB, import it into your Ghidra project then open it
with Ghidra's CodeBrowser. In CodeBrowser, select the
"File -> Export Program..." menu option. Select "GTIRB Exporter" in the format
dropdown to create a GTIRB file for the current program.

## Usage - headless

The `export-gtirb` script is provided to automatically use Ghidra to create a
GTIRB file. Simply provide an input binary and the output filename.

```sh
./scripts/export-gtirb /bin/true ~/true.gtirb
```
