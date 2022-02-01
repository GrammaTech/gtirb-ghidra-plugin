# Define some common environment variables for use in bash scripts that use
# Ghidra's headless analyzer.
[ "x$BASH_VERSION" = "x" ] && exit 1

PLUGIN_REPO="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")"

# Set defaults to values that work in the Docker image, where this is used.
#
DEFAULT_GHIDRA_INSTALL_DIR=/ghidra
DEFAULT_GHIDRA_PROJECT=/home/testdir/Project

# Try to use a writeable location for the default Ghidra project
if [[ ! -w /home ]] && [[ ! -w /home/testdir ]]; then
    DEFAULT_GHIDRA_PROJECT="$PLUGIN_REPO/GhidraProject"
fi

# Attempt to read GHIDRA_INSTALL_DIR from Gradle properties if we can
GRADLE_PROPERTIES_LOCAL="$PLUGIN_REPO/Ghidra/gradle.properties"
GRADLE_PROPERTIES_GLOBAL="$HOME/.gradle/gradle.properties"

if [[ -z "$GHIDRA_INSTALL_DIR" ]] && [[ -f "$GRADLE_PROPERTIES_LOCAL" ]]; then
    . "$GRADLE_PROPERTIES_LOCAL"
fi
if [[ -z "$GHIDRA_INSTALL_DIR" ]] && [[ -f "$GRADLE_PROPERTIES_GLOBAL" ]]; then
    . "$GRADLE_PROPERTIES_GLOBAL"
fi

# Gradle wrapper that attempts to find a good gradle install
find_gradle() {
    # Find the most recent gradle 7.x in PLUGIN_REPO or ~/.local
    GRADLE_DIR=$(ls -1d $PLUGIN_REPO/gradle-7.* 2>/dev/null | tail -n 1)
    if [[ -z "$GRADLE_DIR" ]]; then
        GRADLE_DIR="$(ls -1d $HOME/.local/gradle-7.* 2>/dev/null | tail -n 1)"
    fi

    # If no extracted release was found, check the gradle version in $PATH
    if [[ -z "$GRADLE_DIR" ]]; then
        if ! command gradle --version 2>/dev/null | grep -Fq "Gradle 7."; then
            echo -e "
Error: Gradle 7 is not installed.
Please download a Gradle 7 release from https://gradle.org/releases/ and extract it to:
  $PLUGIN_REPO/" >&2
            return 1
        fi
        echo gradle
    else
        echo "$GRADLE_DIR/bin/gradle"
    fi
}
gradle() {
    if [[ -z "$GRADLE_BIN" ]]; then
        GRADLE_BIN=$(find_gradle) || return 1
    fi
    command "$GRADLE_BIN" "$@"
}

# Use these defaults if (and only if) no environment variables
GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR-$DEFAULT_GHIDRA_INSTALL_DIR}
GHIDRA_PROJECT=${GHIDRA_PROJECT-$DEFAULT_GHIDRA_PROJECT}

# Determine some extra paths based on the above settings
HEADLESS_LAUNCH="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
PROJECT_LOCATION=$(dirname "${GHIDRA_PROJECT}")
PROJECT_NAME=$(basename "${GHIDRA_PROJECT}")

ghidra_headless() {
    "$HEADLESS_LAUNCH" "$PROJECT_LOCATION" "$PROJECT_NAME" "$@" -overwrite
}
