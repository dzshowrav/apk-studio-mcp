#!/data/data/com.termux/files/usr/bin/node

/**
 * APK Studio MCP Server
 * Model Context Protocol (MCP) server for Android APK reverse engineering,
 * decompilation, static analysis, repacking, patching, and signing.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { exec, execFile } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { fileURLToPath } from "url";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_KEYSTORE = path.join(__dirname, "debug.keystore");

// Helper to check tool availability
async function checkCommand(cmd) {
  try {
    await execAsync(`command -v ${cmd}`);
    return true;
  } catch {
    return false;
  }
}

// Ensure debug keystore exists
async function ensureDebugKeystore() {
  if (fs.existsSync(DEFAULT_KEYSTORE)) return DEFAULT_KEYSTORE;
  try {
    const hasKeytool = await checkCommand("keytool");
    if (hasKeytool) {
      await execAsync(
        `keytool -genkey -v -keystore "${DEFAULT_KEYSTORE}" -alias androiddebugkey -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"`
      );
      return DEFAULT_KEYSTORE;
    }
  } catch (err) {
    console.error("Warning: Could not auto-generate debug keystore:", err.message);
  }
  return null;
}

const server = new Server(
  {
    name: "apk-studio-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool Definitions
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "apk_info",
        description:
          "Extract rich metadata from an APK (Package name, version, min/target SDK, permissions, activities, native ABIs, certificates)",
        inputSchema: {
          type: "object",
          properties: {
            apkPath: {
              type: "string",
              description: "Absolute or relative path to the APK file",
            },
          },
          required: ["apkPath"],
        },
      },
      {
        name: "apk_decompile",
        description:
          "Decompile an APK using apktool into Smali assembly, AndroidManifest.xml, and decoded resources",
        inputSchema: {
          type: "object",
          properties: {
            apkPath: {
              type: "string",
              description: "Path to the target APK",
            },
            outputDir: {
              type: "string",
              description: "Destination folder for decompiled project (optional)",
            },
            noSrc: {
              type: "boolean",
              description: "Skip decoding smali code (faster, resources only)",
            },
            noRes: {
              type: "boolean",
              description: "Skip decoding resources (smali only)",
            },
            force: {
              type: "boolean",
              description: "Force overwrite existing directory if it exists",
            },
          },
          required: ["apkPath"],
        },
      },
      {
        name: "apk_build",
        description:
          "Recompile a decompiled APK folder back into an installable APK using apktool",
        inputSchema: {
          type: "object",
          properties: {
            sourceDir: {
              type: "string",
              description: "Path to the decompiled project folder containing apktool.yml",
            },
            outputApk: {
              type: "string",
              description: "Path where the built APK should be saved (optional)",
            },
            useAapt2: {
              type: "boolean",
              description: "Enable AAPT2 for rebuilding (recommended, default: true)",
            },
          },
          required: ["sourceDir"],
        },
      },
      {
        name: "apk_align",
        description:
          "Zipalign an APK file to 4-byte boundaries for runtime performance and OS compatibility",
        inputSchema: {
          type: "object",
          properties: {
            inputApk: {
              type: "string",
              description: "Path to the unaligned APK",
            },
            outputApk: {
              type: "string",
              description: "Path for the aligned APK",
            },
            verifyOnly: {
              type: "boolean",
              description: "Check alignment without creating a new file",
            },
          },
          required: ["inputApk"],
        },
      },
      {
        name: "apk_sign",
        description:
          "Sign an APK with apksigner using a custom keystore or default Android debug keystore",
        inputSchema: {
          type: "object",
          properties: {
            apkPath: {
              type: "string",
              description: "Path to the APK file to sign",
            },
            outputApk: {
              type: "string",
              description: "Path to write signed APK (optional, overwrites input if omitted)",
            },
            keystorePath: {
              type: "string",
              description: "Path to .keystore or .jks file (defaults to debug keystore)",
            },
            alias: {
              type: "string",
              description: "Key alias (defaults to androiddebugkey)",
            },
            storePass: {
              type: "string",
              description: "Keystore password (defaults to android)",
            },
            keyPass: {
              type: "string",
              description: "Key password (defaults to android)",
            },
          },
          required: ["apkPath"],
        },
      },
      {
        name: "apk_verify",
        description:
          "Verify APK signature scheme (v1, v2, v3, v4) and certificate details using apksigner",
        inputSchema: {
          type: "object",
          properties: {
            apkPath: {
              type: "string",
              description: "Path to the APK to verify",
            },
          },
          required: ["apkPath"],
        },
      },
      {
        name: "apk_extract_dex",
        description:
          "Extract classes.dex (classes*.dex) from an APK without full decompilation",
        inputSchema: {
          type: "object",
          properties: {
            apkPath: {
              type: "string",
              description: "Path to the APK file",
            },
            outputDir: {
              type: "string",
              description: "Directory to extract DEX files to",
            },
          },
          required: ["apkPath"],
        },
      },
      {
        name: "apk_dex2jar",
        description:
          "Convert classes.dex or APK into a Java JAR file using dex2jar for JD-GUI / CFR analysis",
        inputSchema: {
          type: "object",
          properties: {
            inputPath: {
              type: "string",
              description: "Path to .dex or .apk file",
            },
            outputJar: {
              type: "string",
              description: "Path to output .jar file (optional)",
            },
          },
          required: ["inputPath"],
        },
      },
      {
        name: "apk_search_code",
        description:
          "Fast search across decompiled smali, xml, or assets for methods, API keys, URLs, or signatures",
        inputSchema: {
          type: "object",
          properties: {
            directory: {
              type: "string",
              description: "Target directory (decompiled APK root)",
            },
            pattern: {
              type: "string",
              description: "Regex pattern or string to search for",
            },
            fileExt: {
              type: "string",
              description: "File extension filter (e.g. 'smali', 'xml', 'json')",
            },
            maxResults: {
              type: "number",
              description: "Maximum number of results to return (default: 50)",
            },
          },
          required: ["directory", "pattern"],
        },
      },
      {
        name: "apk_patch_file",
        description:
          "Patch or replace instructions/text in a decompiled file (Smali, XML, or asset)",
        inputSchema: {
          type: "object",
          properties: {
            filePath: {
              type: "string",
              description: "Path to the file to modify",
            },
            findPattern: {
              type: "string",
              description: "Exact text or regex pattern to find",
            },
            replacement: {
              type: "string",
              description: "Replacement text",
            },
            isRegex: {
              type: "boolean",
              description: "Whether findPattern should be treated as regex (default: false)",
            },
          },
          required: ["filePath", "findPattern", "replacement"],
        },
      },
      {
        name: "apk_list_contents",
        description:
          "Inspect internal file list of an APK archive (assets, libs, resources, meta-inf) with compression stats",
        inputSchema: {
          type: "object",
          properties: {
            apkPath: {
              type: "string",
              description: "Path to the APK file",
            },
            filter: {
              type: "string",
              description: "Optional filter wildcard or substring (e.g. 'lib/', 'assets/')",
            },
          },
          required: ["apkPath"],
        },
      },
    ],
  };
});

// Tool Handler Execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "apk_info": {
        const apkPath = path.resolve(args.apkPath);
        if (!fs.existsSync(apkPath)) {
          throw new Error(`File not found: ${apkPath}`);
        }

        let infoText = "";
        const aaptCmd = (await checkCommand("aapt2"))
          ? "aapt2 dump badging"
          : (await checkCommand("aapt"))
          ? "aapt dump badging"
          : null;

        if (aaptCmd) {
          try {
            const { stdout } = await execAsync(`${aaptCmd} "${apkPath}"`);
            infoText = stdout;
          } catch (err) {
            infoText = `AAPT dump failed: ${err.message}\n`;
          }
        }

        // Parse key metadata fields
        const pkgMatch = infoText.match(/package: name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']+)'/);
        const minSdkMatch = infoText.match(/sdkVersion:'([^']+)'/);
        const targetSdkMatch = infoText.match(/targetSdkVersion:'([^']+)'/);
        const labelMatch = infoText.match(/application-label:'([^']+)'/);
        const permissions = [...infoText.matchAll(/uses-permission: name='([^']+)'/g)].map((m) => m[1]);
        const nativeAbis = [...infoText.matchAll(/native-code: '([^']+)'/g)].map((m) => m[1]);
        const launchable = infoText.match(/launchable-activity: name='([^']+)'/);

        // Fallback zip inspection if aapt output was minimal
        let zipStats = "";
        try {
          const { stdout } = await execAsync(`unzip -l "${apkPath}" | head -n 35`);
          zipStats = stdout;
        } catch {
          // ignore if unzip missing
        }

        const summary = {
          file: apkPath,
          sizeBytes: fs.statSync(apkPath).size,
          package: pkgMatch ? pkgMatch[1] : "Unknown (install aapt for complete info)",
          versionCode: pkgMatch ? pkgMatch[2] : "Unknown",
          versionName: pkgMatch ? pkgMatch[3] : "Unknown",
          sdkVersion: minSdkMatch ? minSdkMatch[1] : "Unknown",
          targetSdkVersion: targetSdkMatch ? targetSdkMatch[1] : "Unknown",
          applicationLabel: labelMatch ? labelMatch[1] : "Unknown",
          launchableActivity: launchable ? launchable[1] : "None",
          permissionsCount: permissions.length,
          permissions: permissions.slice(0, 30),
          nativeABIs: nativeAbis.length > 0 ? nativeAbis : "No native libraries detected",
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(summary, null, 2) + "\n\n--- Archive Sample ---\n" + zipStats,
            },
          ],
        };
      }

      case "apk_decompile": {
        const apkPath = path.resolve(args.apkPath);
        if (!fs.existsSync(apkPath)) throw new Error(`APK file not found: ${apkPath}`);

        const outDir = args.outputDir
          ? path.resolve(args.outputDir)
          : path.join(path.dirname(apkPath), path.basename(apkPath, ".apk") + "_decompiled");

        const hasApktool = await checkCommand("apktool");
        if (!hasApktool) throw new Error("apktool command is not installed or not in PATH.");

        let cmd = `apktool d "${apkPath}" -o "${outDir}"`;
        if (args.force !== false) cmd += " -f";
        if (args.noSrc) cmd += " -s";
        if (args.noRes) cmd += " -r";

        const { stdout, stderr } = await execAsync(cmd);
        return {
          content: [
            {
              type: "text",
              text: `[+] APK Decompiled Successfully to: ${outDir}\n\n${stdout || ""}\n${stderr || ""}`,
            },
          ],
        };
      }

      case "apk_build": {
        const sourceDir = path.resolve(args.sourceDir);
        if (!fs.existsSync(sourceDir)) throw new Error(`Source folder not found: ${sourceDir}`);

        const apktoolYaml = path.join(sourceDir, "apktool.yml");
        if (!fs.existsSync(apktoolYaml)) {
          throw new Error(`Directory does not appear to be an apktool project (missing apktool.yml): ${sourceDir}`);
        }

        const outApk = args.outputApk
          ? path.resolve(args.outputApk)
          : path.join(path.dirname(sourceDir), path.basename(sourceDir) + "_rebuilt.apk");

        const hasApktool = await checkCommand("apktool");
        if (!hasApktool) throw new Error("apktool is not installed or not in PATH.");

        let cmd = `apktool b "${sourceDir}" -o "${outApk}"`;
        if (args.useAapt2 !== false) {
          cmd += " --use-aapt2";
        }

        const { stdout, stderr } = await execAsync(cmd);
        return {
          content: [
            {
              type: "text",
              text: `[+] APK Rebuilt Successfully: ${outApk}\n\n${stdout || ""}\n${stderr || ""}`,
            },
          ],
        };
      }

      case "apk_align": {
        const inputApk = path.resolve(args.inputApk);
        if (!fs.existsSync(inputApk)) throw new Error(`Input APK not found: ${inputApk}`);

        const hasZipalign = await checkCommand("zipalign");
        if (!hasZipalign) throw new Error("zipalign command is not installed or not in PATH.");

        if (args.verifyOnly) {
          const { stdout, stderr } = await execAsync(`zipalign -c -v 4 "${inputApk}"`);
          return {
            content: [
              {
                type: "text",
                text: `[+] Zipalign Verification for ${inputApk}:\n${stdout || ""}\n${stderr || ""}`,
              },
            ],
          };
        }

        const outputApk = args.outputApk
          ? path.resolve(args.outputApk)
          : inputApk.replace(/\.apk$/i, "_aligned.apk");

        const { stdout, stderr } = await execAsync(`zipalign -p -f -v 4 "${inputApk}" "${outputApk}"`);
        return {
          content: [
            {
              type: "text",
              text: `[+] APK Zipalign complete: ${outputApk}\n${stdout || ""}\n${stderr || ""}`,
            },
          ],
        };
      }

      case "apk_sign": {
        const apkPath = path.resolve(args.apkPath);
        if (!fs.existsSync(apkPath)) throw new Error(`APK file not found: ${apkPath}`);

        const hasApksigner = await checkCommand("apksigner");
        if (!hasApksigner) throw new Error("apksigner is not installed or not in PATH.");

        let ks = args.keystorePath ? path.resolve(args.keystorePath) : await ensureDebugKeystore();
        if (!ks || !fs.existsSync(ks)) {
          throw new Error("Keystore file not found and debug keystore could not be generated.");
        }

        const alias = args.alias || "androiddebugkey";
        const storePass = args.storePass || "android";
        const keyPass = args.keyPass || "android";

        let outApk = args.outputApk ? path.resolve(args.outputApk) : apkPath;

        const cmd = `apksigner sign --ks "${ks}" --ks-key-alias "${alias}" --ks-pass "pass:${storePass}" --key-pass "pass:${keyPass}" --out "${outApk}" "${apkPath}"`;
        const { stdout, stderr } = await execAsync(cmd);

        return {
          content: [
            {
              type: "text",
              text: `[+] APK Signed Successfully: ${outApk}\nKeystore: ${ks}\nAlias: ${alias}\n${stdout || ""}\n${stderr || ""}`,
            },
          ],
        };
      }

      case "apk_verify": {
        const apkPath = path.resolve(args.apkPath);
        if (!fs.existsSync(apkPath)) throw new Error(`APK not found: ${apkPath}`);

        const hasApksigner = await checkCommand("apksigner");
        if (!hasApksigner) throw new Error("apksigner is not installed or not in PATH.");

        try {
          const { stdout, stderr } = await execAsync(`apksigner verify --verbose "${apkPath}"`);
          return {
            content: [
              {
                type: "text",
                text: `[+] Verification Results for ${apkPath}:\n\n${stdout || ""}\n${stderr || ""}`,
              },
            ],
          };
        } catch (err) {
          return {
            content: [
              {
                type: "text",
                text: `[-] Verification Failed: ${err.stdout || err.message}\n${err.stderr || ""}`,
              },
            ],
          };
        }
      }

      case "apk_extract_dex": {
        const apkPath = path.resolve(args.apkPath);
        if (!fs.existsSync(apkPath)) throw new Error(`APK not found: ${apkPath}`);

        const outDir = args.outputDir
          ? path.resolve(args.outputDir)
          : path.join(path.dirname(apkPath), path.basename(apkPath, ".apk") + "_dex");

        if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

        const { stdout, stderr } = await execAsync(`unzip -o -q "${apkPath}" "*.dex" -d "${outDir}"`);
        const extracted = fs.readdirSync(outDir).filter((f) => f.endsWith(".dex"));

        return {
          content: [
            {
              type: "text",
              text: `[+] Extracted ${extracted.length} DEX files to: ${outDir}\nFiles: ${extracted.join(", ")}`,
            },
          ],
        };
      }

      case "apk_dex2jar": {
        const inputPath = path.resolve(args.inputPath);
        if (!fs.existsSync(inputPath)) throw new Error(`Target file not found: ${inputPath}`);

        const d2jCmd = (await checkCommand("d2j-dex2jar"))
          ? "d2j-dex2jar"
          : (await checkCommand("dex2jar"))
          ? "dex2jar"
          : null;

        if (!d2jCmd) {
          throw new Error("dex2jar / d2j-dex2jar is not installed on this system.");
        }

        const outJar = args.outputJar
          ? path.resolve(args.outputJar)
          : inputPath.replace(/\.(dex|apk)$/i, "-dex2jar.jar");

        const { stdout, stderr } = await execAsync(`${d2jCmd} -f -o "${outJar}" "${inputPath}"`);
        return {
          content: [
            {
              type: "text",
              text: `[+] DEX converted to JAR: ${outJar}\n${stdout || ""}\n${stderr || ""}`,
            },
          ],
        };
      }

      case "apk_search_code": {
        const dir = path.resolve(args.directory);
        if (!fs.existsSync(dir)) throw new Error(`Directory not found: ${dir}`);

        const pattern = args.pattern;
        const ext = args.fileExt ? `-name "*.${args.fileExt.replace(/^\./, "")}"` : "";
        const max = args.maxResults || 50;

        // Use grep with safe escaping
        const escaped = pattern.replace(/"/g, '\\"');
        const cmd = `grep -rnI ${ext ? `--include="${ext}"` : ""} "${escaped}" "${dir}" 2>/dev/null | head -n ${max}`;
        const { stdout } = await execAsync(cmd);

        return {
          content: [
            {
              type: "text",
              text: stdout.trim()
                ? `[+] Search Results for "${pattern}":\n\n${stdout}`
                : `[-] No matches found for pattern "${pattern}" in ${dir}`,
            },
          ],
        };
      }

      case "apk_patch_file": {
        const filePath = path.resolve(args.filePath);
        if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);

        const content = fs.readFileSync(filePath, "utf-8");
        let modified = "";

        if (args.isRegex) {
          const regex = new RegExp(args.findPattern, "g");
          if (!regex.test(content)) {
            throw new Error(`Regex pattern '${args.findPattern}' did not match any content in ${filePath}`);
          }
          modified = content.replace(regex, args.replacement);
        } else {
          if (!content.includes(args.findPattern)) {
            throw new Error(`Target text pattern was not found in ${filePath}`);
          }
          modified = content.split(args.findPattern).join(args.replacement);
        }

        fs.writeFileSync(filePath, modified, "utf-8");

        return {
          content: [
            {
              type: "text",
              text: `[+] File successfully patched: ${filePath}\nBytes: ${modified.length}`,
            },
          ],
        };
      }

      case "apk_list_contents": {
        const apkPath = path.resolve(args.apkPath);
        if (!fs.existsSync(apkPath)) throw new Error(`APK file not found: ${apkPath}`);

        let cmd = `unzip -l "${apkPath}"`;
        if (args.filter) {
          cmd += ` | grep -i "${args.filter}"`;
        }

        const { stdout } = await execAsync(cmd);
        return {
          content: [
            {
              type: "text",
              text: `[+] Contents of ${apkPath}:\n\n${stdout || "No matching entries."}`,
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    return {
      content: [
        {
          type: "text",
          text: `[ERROR] Execution failed for tool "${name}": ${err.message}`,
        },
      ],
      isError: true,
    };
  }
});

// Server Initialization
async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("APK Studio MCP Server running on stdio transport.");
}

run().catch((error) => {
  console.error("Fatal error starting APK Studio MCP server:", error);
  process.exit(1);
});
