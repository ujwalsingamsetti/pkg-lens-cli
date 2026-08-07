# 🔍 `pkg-lens-cli`

> **Pre-install security, license safety, OSV vulnerability scanner & bundle footprint inspector CLI tool and library for npm packages.**

[![npm version](https://img.shields.io/npm/v/pkg-lens-cli.svg?color=blue)](https://www.npmjs.com/package/pkg-lens-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)

`pkg-lens-cli` gives developers complete visibility into npm packages **before** running `npm install`. It audits supply-chain security risks, dangerous lifecycle scripts (`preinstall`/`postinstall` hooks), real-time Google OSV CVE vulnerabilities, typosquatting attack patterns, minified & gzipped bundle sizes, tree-shakeability, license safety, and maintainability metrics.

---

## ⚡ Key Features

* **🛡️ Safety Score (0 - 100)**: Real-time security score where **100/100 represents 100% safe & zero risk**.
* **🐛 Real-Time OSV CVE Scanner**: Queries Google's OSV.dev database for real-time CVE vulnerabilities and GHSA security advisories.
* **🕵️ Typosquatting Risk Detector**: Detects suspicious package names attempting typosquatting supply-chain attacks.
* **⚠️ Lifecycle Script Auditor**: Flags `preinstall` or `postinstall` shell hooks that could execute arbitrary code during `npm install`.
* **📦 Bundle Footprint Analysis**: Calculates minified size, gzipped size impact, and tree-shaking capabilities before downloading.
* **📜 License Compliance Checker**: Classifies licenses into Permissive (`MIT`/`Apache-2.0`), Copyleft (`GPL`), or Proprietary/Unknown risks.
* **⚔️ Side-by-Side Comparison Matrix**: Compare competing packages (e.g. `express` vs `fastify` or `axios` vs `got`) in a single command.
* **🤖 CI/CD Pipeline Automation**: Supports `--json` flag for automated security pipeline assertions.

---

## 🚀 Quick Start (CLI Usage)

No installation required — inspect any package directly using `npx`:

```bash
# 1. Inspect any npm package (latest version)
npx pkg-lens-cli express

# 2. Inspect a specific version
npx pkg-lens-cli lodash@4.17.11

# 3. Compare two packages side-by-side
npx pkg-lens-cli express --vs fastify

# 4. Export raw JSON for CI/CD automation
npx pkg-lens-cli lodash --json
```

---

## 📖 Complete Metric Legend

| Metric | Evaluation & Meaning |
| :--- | :--- |
| **Safety Score** | **100/100 (SAFE)** = Clean audit with zero risk factors.<br>**75-99/100 (MODERATE)** = Minor warnings (older release or 1 maintainer).<br>**< 50/100 (CRITICAL)** = Deprecated package, reported CVE vulnerabilities, or dangerous install hooks! |
| **Vulnerabilities (CVE)** | **✅ Clean**: Zero reported OSV advisories.<br>**⚠️ 7 Advisories**: Lists exact GHSA/CVE advisory titles & IDs from Google's OSV database. |
| **Typosquatting Risk** | **⚠️ Possible Typosquat**: Flags package names suspiciously similar to top popular npm targets (e.g. `expresss` vs `express`). |
| **Install Scripts** | **✅ Safe**: No lifecycle execution hooks.<br>**⚠️ 2 Hooks Detected**: Contains `preinstall` or `postinstall` shell commands. |
| **Bundle Size (Gzip)** | Minified & compressed download payload impact on your end-user bundles. |
| **Tree-Shakeable** | **Yes ✅**: Supports modern ES Modules (`import`/`export`) and side-effect-free exports.<br>**No ⚠️**: Legacy CommonJS structure. |
| **License Safety** | **Permissive**: `MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`.<br>**Copyleft**: `GPL-3.0`, `AGPL-3.0`, `MPL-2.0`. |

---

## 💻 Programmatic API Usage

You can also use `pkg-lens-cli` as a Node.js library in your applications:

```bash
npm install pkg-lens-cli
```

```javascript
import { inspectPackage, comparePackages } from 'pkg-lens-cli';

// Inspect a package programmatically
const reportText = await inspectPackage('express');
console.log(reportText);

// Return JSON object for automated checks
const data = await inspectPackage('axios', { json: true });
console.log(`Safety Score: ${data.security.safetyScore}/100`);
console.log(`Gzip Size: ${data.footprint.gzippedFormatted}`);
console.log(`Vulnerabilities: ${data.vulnerabilities.length}`);

// Compare two packages side-by-side
const comparison = await comparePackages('express', 'fastify');
console.log(comparison.matrixTable);
```

---

## ⚙️ Global CLI Installation (Optional)

Install `pkg-lens-cli` globally to use `pkg-lens-cli` directly from anywhere in your shell:

```bash
npm install -g pkg-lens-cli
```

Then run directly:
```bash
pkg-lens-cli dayjs
pkg-lens-cli express --vs fastify
```

---

## 🧪 Testing

Run the native automated unit test suite:

```bash
npm test
```

---

## 📄 License

MIT © Ujwal Singamsetti
