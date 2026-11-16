# APK Studio MCP (`apk-studio-mcp`)

A powerful **Model Context Protocol (MCP)** server providing autonomous Android APK reverse engineering, static analysis, decompilation, code search, bytecode patching, repacking, zipalign, and cryptographic signing.

Designed for security researchers, reverse engineers, and developers working on Termux (Android aarch64) as well as Linux / macOS environments.

---

## 🚀 Key Features & MCP Tools

| Tool | Description |
| :--- | :--- |
| `apk_info` | Extracts deep metadata (Package name, versions, min/target SDK, permissions, activities, native ABIs, certificates). |
| `apk_decompile` | Full decompilation of APK into Smali code, decoded resources, and `AndroidManifest.xml` via `apktool`. |
| `apk_build` | Rebuilds decompiled project directory back into an APK using `apktool` (with AAPT/AAPT2 support). |
| `apk_align` | Aligns APK 4-byte boundaries with `zipalign` or verifies existing alignment. |
| `apk_sign` | Cryptographically signs APK using `apksigner` with custom keystore or auto-generated debug key. |
| `apk_verify` | Verifies signature schemes (v1, v2, v3, v4) and certificate fingerprints using `apksigner`. |
| `apk_extract_dex` | Unpacks all `classes*.dex` files directly from an APK without full decompilation. |
| `apk_dex2jar` | Converts `.dex` or `.apk` files into `.jar` format for JD-GUI, CFR, or Procyon analysis. |
| `apk_search_code` | Ultra-fast regex / string search across decompiled Smali files, assets, and XML manifests. |
| `apk_patch_file` | Direct targeted replacement of bytecode instructions, method returns, or strings in Smali files. |
| `apk_list_contents` | Inspects internal APK archive structure (lib, assets, res, META-INF) with compression stats. |

---

## 📦 Directory Structure

```text
apk-studio-mcp/
├── .gitignore          # Git exclusion rules for node_modules, build artifacts & keystores
├── package.json        # MCP Server manifest & SDK dependencies
├── install.sh          # Automated installer for Termux / Debian / Ubuntu / Arch
├── index.js            # Main MCP Server implementation (stdio transport)
└── README.md           # Documentation & usage guide
```

---

## 🛠️ Installation & Setup

### 1. Run Automated Setup Script

The included `install.sh` script automatically detects your environment (Termux vs Standard Linux), installs required binary packages (`openjdk-17`, `apktool`, `aapt`, `apksigner`, `zipalign`), runs `npm install`, and generates an Android debug keystore.

```bash
cd apk-studio-mcp
chmod +x install.sh index.js
./install.sh
```

### 2. Manual Package Setup (Termux)

If you prefer installing dependencies manually on Termux:

```bash
pkg update -y
pkg install -y openjdk-17 apktool aapt aapt2 apksigner dex2jar android-tools unzip zip nodejs
cd apk-studio-mcp
npm install
```

### 3. Manual Package Setup (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y openjdk-17-jdk aapt zipalign apksigner unzip zip curl nodejs npm
cd apk-studio-mcp
npm install
```

---

## ⚙️ MCP Client Configuration

### Antigravity / Claude Desktop / Cursor Config

Add this server to your MCP configuration file (e.g., `~/.gemini/antigravity-cli/mcp.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "apk-studio": {
      "command": "node",
      "args": [
        "/data/data/com.termux/files/home/apk-studio-mcp/index.js"
      ]
    }
  }
}
```

---

## 🎯 Typical Reverse Engineering Workflow

1. **Inspect APK**:
   Call `apk_info` with `apkPath: "/path/to/target.apk"` to check permissions, components, and ABIs.
2. **Decompile**:
   Call `apk_decompile` to extract Smali and manifest files.
3. **Locate Target Logic**:
   Call `apk_search_code` to find sensitive endpoints, root detection checks, or SSL pinning logic.
4. **Patch Smali**:
   Call `apk_patch_file` to modify validation methods (e.g., returning `0x1` or bypassing checks).
5. **Rebuild & Repack**:
   Call `apk_build` to recompile the project into a new APK.
6. **Align & Sign**:
   Call `apk_align` followed by `apk_sign` using the integrated debug keystore.
7. **Verify**:
   Call `apk_verify` to ensure the APK is properly signed and ready for installation.

---

## 📄 License

MIT License. Designed and maintained for security research and developer tooling.
