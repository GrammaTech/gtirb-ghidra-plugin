# Define some common environment variables for use in bash scripts that use
# Ghidra's headless analyzer.
[ "x$BASH_VERSION" = "x" ] && exit 1

# Set defaults to values that work in the Docker image, where this is used.
#
DEFAULT_GHIDRA_INSTALL_DIR=/ghidra
DEFAULT_GHIDRA_PROJECT=/home/testdir/Project

# Try to use a writeable location for the default Ghidra project
if [[ ! -w /home ]] && [[ ! -w /home/testdir ]]; then
    DEFAULT_GHIDRA_PROJECT="$HOME/GhidraTestProject"
fi

# Attempt to read GHIDRA_INSTALL_DIR from Gradle properties if we can
GRADLE_PROPERTIES_LOCAL=$(dirname "${BASH_SOURCE[0]}")/../Ghidra/gradle.properties
GRADLE_PROPERTIES_GLOBAL="$HOME/.gradle/gradle.properties"

if [[ -z "$GHIDRA_INSTALL_DIR" ]] && [[ -f "$GRADLE_PROPERTIES_LOCAL" ]]; then
    . "$GRADLE_PROPERTIES_LOCAL"
fi
if [[ -z "$GHIDRA_INSTALL_DIR" ]] && [[ -f "$GRADLE_PROPERTIES_GLOBAL" ]]; then
    . "$GRADLE_PROPERTIES_GLOBAL"
fi

# Use these defaults if (and only if) no environment variables
GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR-$DEFAULT_GHIDRA_INSTALL_DIR}
GHIDRA_PROJECT=${GHIDRA_PROJECT-$DEFAULT_GHIDRA_PROJECT}

# Determine some extra paths based on the above settings
HEADLESS_LAUNCH="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
PROJECT_LOCATION=$(dirname "${GHIDRA_PROJECT}")
PROJECT_NAME=$(basename "${GHIDRA_PROJECT}")
