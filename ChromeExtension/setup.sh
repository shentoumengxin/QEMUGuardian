#!/bin/bash

echo "======================================================="
echo "Qemu Guardian Native Host Installation Script (Linux)"
echo "======================================================="
echo ""

# --- 1. Get Chrome Extension ID ---
read -p "Please enter your Chrome Extension ID (e.g., abcdefghijklmnopqrstuvwxyzabcdef): " CHROME_EXTENSION_ID
if [ -z "$CHROME_EXTENSION_ID" ]; then
    echo "Error: Chrome Extension ID cannot be empty. Exiting."
    exit 1
fi

# Chrome Extension IDs are 32 characters long and contain only lowercase 'a' through 'p'
if [[ ! "$CHROME_EXTENSION_ID" =~ ^[a-p]{32}$ ]]; then
    echo "Error: Invalid Chrome Extension ID format."
    echo "ID must be exactly 32 characters long and contain only lowercase letters 'a' through 'p'."
    exit 1
fi

# --- 2. Define Paths ---
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
BIN_DIR="${SCRIPT_DIR}/bin/linux"
EXECUTABLE_NAME="Guardian"
EXECUTABLE_SOURCE_PATH="${BIN_DIR}/${EXECUTABLE_NAME}"
MANIFEST_TEMPLATE_PATH="${SCRIPT_DIR}/guardian_manifest.json.template"
NATIVE_HOST_NAME="com.nus_dada_group.guardian"

# --- 3. Validate Source Files ---
if [ ! -f "$EXECUTABLE_SOURCE_PATH" ]; then
    echo "Error: ${EXECUTABLE_NAME} not found at \"${EXECUTABLE_SOURCE_PATH}\". Please build it first."
    exit 1
fi
if [ ! -f "$MANIFEST_TEMPLATE_PATH" ]; then
    echo "Error: guardian_manifest.json.template not found at \"${MANIFEST_TEMPLATE_PATH}\"."
    exit 1
fi

# --- 4. Get User Defined Install Location for Backend Service ---
echo ""
echo "--- Backend Service Installation Path ---"
echo "The Guardian executable will be copied to this location."
echo "Default path: ${BIN_DIR} (current compiled location)"
read -p "Enter installation path for Guardian (or press Enter for default): " INSTALL_PATH_RAW

if [ -z "$INSTALL_PATH_RAW" ]; then
    INSTALL_PATH="${BIN_DIR}"
else
    # 先替换 ~ 为 $HOME
    EXPANDED_PATH=$(echo "$INSTALL_PATH_RAW" | sed "s|^~|$HOME|")
    # 然后使用 realpath
    if command -v realpath &> /dev/null; then
        INSTALL_PATH=$(realpath "$EXPANDED_PATH")
    else
        INSTALL_PATH=$EXPANDED_PATH
    fi
fi

echo "Selected installation path: ${INSTALL_PATH}"
echo ""

# --- 5. Create Installation Directory and Copy Files ---
echo "Creating installation directory: ${INSTALL_PATH}"
mkdir -p "${INSTALL_PATH}"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create directory \"${INSTALL_PATH}\". Please check permissions."
    exit 1
fi

echo "Copying ${EXECUTABLE_NAME} to \"${INSTALL_PATH}\"..."
cp "${EXECUTABLE_SOURCE_PATH}" "${INSTALL_PATH}/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy executable to \"${INSTALL_PATH}\"."
    exit 1
fi
chmod +x "${INSTALL_PATH}/${EXECUTABLE_NAME}" # Ensure execute permissions
if [ $? -ne 0 ]; then
    echo "Warning: Failed to set execute permissions for \"${INSTALL_PATH}/${EXECUTABLE_NAME}\"."
fi
ACTUAL_EXECUTABLE_PATH="${INSTALL_PATH}/${EXECUTABLE_NAME}"

# --- 6. Generate Native Host Manifest ---
echo "Generating Native Host manifest..."

# Choose where to place the manifest file
echo ""
echo "--- Native Host Manifest Location ---"
echo "Choose where to install the Native Host manifest file (*.json):"
echo "1) Install for current user only (~/.config/google-chrome/NativeMessagingHosts/)"
echo "2) Install system-wide (/etc/opt/chrome/native-messaging-hosts/) - Requires sudo"
read -p "Enter choice (1 or 2): " MANIFEST_CHOICE

MANIFEST_TARGET_DIR=""
case "$MANIFEST_CHOICE" in
    1)
        MANIFEST_TARGET_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
        ;;
    2)
        MANIFEST_TARGET_DIR="/etc/opt/chrome/native-messaging-hosts"
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

mkdir -p "$MANIFEST_TARGET_DIR"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create manifest directory \"${MANIFEST_TARGET_DIR}\". Check permissions."
    exit 1
fi

GENERATED_MANIFEST_PATH="${MANIFEST_TARGET_DIR}/${NATIVE_HOST_NAME}.json"

# Replace placeholders in template and save to target location
sed -e "s|YOUR_EXTENSION_ID_PLACEHOLDER|${CHROME_EXTENSION_ID}|g" \
    -e "s|YOUR_GUARDIAN_EXECUTABLE_PATH_PLACEHOLDER|${ACTUAL_EXECUTABLE_PATH}|g" \
    "${MANIFEST_TEMPLATE_PATH}" > "${GENERATED_MANIFEST_PATH}"

if [ $? -ne 0 ]; then
    echo "Error: Failed to generate or save manifest file."
    exit 1
fi

# If system-wide, use sudo for copying
if [ "$MANIFEST_CHOICE" -eq 2 ]; then
    sudo mv "${GENERATED_MANIFEST_PATH}" "${GENERATED_MANIFEST_PATH}.tmp" # Move to temp
    sudo cp "${GENERATED_MANIFEST_PATH}.tmp" "${GENERATED_MANIFEST_PATH}" # Copy with sudo
    sudo rm "${GENERATED_MANIFEST_PATH}.tmp" # Remove temp
    if [ $? -ne 0 ]; then
        echo "Error: Failed to move manifest with sudo. Check permissions."
        exit 1
    fi
    # Ensure proper permissions for the manifest file
    sudo chmod 644 "${GENERATED_MANIFEST_PATH}"
fi

echo "Native Host manifest created at: ${GENERATED_MANIFEST_PATH}"

echo ""
echo "======================================================="
echo "Installation Complete!"
echo "The Native Host \"${NATIVE_HOST_NAME}\" has been registered."
echo "Guardian executable is located at: \"${ACTUAL_EXECUTABLE_PATH}\""
echo "You can now load/reload the Chrome Extension."
echo "======================================================="
echo ""
