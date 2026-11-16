#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# APK Studio MCP - Automated Installation & Setup Script
# Supports: Termux (Android aarch64/arm), Debian/Ubuntu, Arch, macOS
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================="
echo "    APK Studio MCP - Environment Setup"
echo "=================================================="

# 1. Environment Detection
IS_TERMUX=false
if [ -d "/data/data/com.termux" ] || [ -n "$TERMUX_VERSION" ]; then
    IS_TERMUX=true
    echo "[+] Detected Environment: Termux (Android)"
else
    echo "[+] Detected Environment: Linux / Unix"
fi

# 2. Package Installation
if [ "$IS_TERMUX" = true ]; then
    echo "[*] Updating package repositories..."
    pkg update -y || apt update -y

    echo "[*] Installing required binary dependencies..."
    pkg install -y openjdk-17 apktool aapt aapt2 apksigner dex2jar android-tools unzip zip || {
        echo "[!] Some packages could not be installed in one pass, attempting individually..."
        for pkg_name in openjdk-17 apktool aapt apksigner dex2jar android-tools unzip zip; do
            pkg install -y "$pkg_name" || true
        done
    }
else
    if command -v apt-get >/dev/null 2>&1; then
        echo "[*] Installing system dependencies via apt..."
        sudo apt-get update -y
        sudo apt-get install -y openjdk-17-jdk aapt zipalign apksigner unzip zip curl
        
        # Check apktool
        if ! command -v apktool >/dev/null 2>&1; then
            echo "[*] Fetching apktool wrapper & jar..."
            sudo curl -sSL https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool
            sudo curl -sSL https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -o /usr/local/bin/apktool.jar
            sudo chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar
        fi
    elif command -v pacman >/dev/null 2>&1; then
        echo "[*] Installing dependencies via pacman..."
        sudo pacman -Sy --noconfirm jdk17-openjdk android-tools apktool unzip zip
    fi
fi

# 3. Node.js & NPM Dependencies
echo "[*] Checking Node.js environment..."
if ! command -v node >/dev/null 2>&1; then
    echo "[!] Node.js not found. Installing Node.js..."
    if [ "$IS_TERMUX" = true ]; then
        pkg install -y nodejs
    else
        echo "[!] Please install Node.js (>= 18) manually."
        exit 1
    fi
fi

echo "[*] Installing Node dependencies..."
if [ -f "package.json" ]; then
    npm install
fi

# 4. Generate Default Debug Keystore for APK signing if missing
DEBUG_KEYSTORE="$SCRIPT_DIR/debug.keystore"
if [ ! -f "$DEBUG_KEYSTORE" ]; then
    echo "[*] Generating default debug keystore for automated signing..."
    if command -v keytool >/dev/null 2>&1; then
        keytool -genkey -v \
            -keystore "$DEBUG_KEYSTORE" \
            -alias androiddebugkey \
            -storepass android \
            -keypass android \
            -keyalg RSA \
            -keysize 2048 \
            -validity 10000 \
            -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1 || true
        echo "[+] Debug keystore created at: $DEBUG_KEYSTORE"
    else
        echo "[-] keytool not found yet; keystore generation deferred until Java is in PATH."
    fi
fi

# 5. Permission & Executable Setup
chmod +x "$SCRIPT_DIR/index.js"
chmod +x "$SCRIPT_DIR/install.sh"

# 6. Verification Summary
echo ""
echo "=================================================="
echo "          Environment Verification"
echo "=================================================="
printf "%-18s: %s\n" "Node.js" "$(command -v node >/dev/null && node -v || echo 'NOT FOUND')"
printf "%-18s: %s\n" "NPM" "$(command -v npm >/dev/null && npm -v || echo 'NOT FOUND')"
printf "%-18s: %s\n" "Java (JDK)" "$(command -v java >/dev/null && java -version 2>&1 | head -n 1 || echo 'NOT FOUND')"
printf "%-18s: %s\n" "Apktool" "$(command -v apktool >/dev/null && apktool -version 2>&1 | head -n 1 || echo 'NOT FOUND')"
printf "%-18s: %s\n" "AAPT / AAPT2" "$(command -v aapt2 >/dev/null && echo 'aapt2 available' || (command -v aapt >/dev/null && echo 'aapt available' || echo 'NOT FOUND'))"
printf "%-18s: %s\n" "Apksigner" "$(command -v apksigner >/dev/null && echo 'apksigner available' || echo 'NOT FOUND')"
printf "%-18s: %s\n" "Zipalign" "$(command -v zipalign >/dev/null && echo 'zipalign available' || echo 'NOT FOUND')"
echo "=================================================="
echo "[+] APK Studio MCP setup script completed successfully."
echo "=================================================="
