# 🔍 `pkg-lens-cli`

> **The zero-dependency pre-install security scanner, developer advisor, project auditor & safe package installer for npm.**

[![npm version](https://img.shields.io/npm/v/pkg-lens-cli.svg?color=blue)](https://www.npmjs.com/package/pkg-lens-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![Tests](https://img.shields.io/badge/tests-11%2F11%20passing-brightgreen)](https://github.com/ujwalsingamsetti/pkg-lens-cli)

`pkg-lens-cli` gives developers and teams complete visibility into npm packages **before** running `npm install`. It audits supply-chain security risks, dangerous lifecycle scripts (`preinstall`/`postinstall` hooks), real-time Google OSV CVE vulnerabilities, typosquatting attacks, copyleft license compliance, bundle bloat, and maintainability.

---

## ⚡ What Makes `pkg-lens-cli` Unique?

1. **🛡️ Safe Install Guardian (`add`)**: Replace `npm install <pkg>` with `pkg-lens-cli add <pkg>`. It runs a security pre-check and displays a safety summary card *before* asking if you want to proceed.
2. **📊 Local Project Dependency Auditor (`audit`)**: Run `pkg-lens-cli audit` in any repository to scan all `dependencies` and `devDependencies` in `package.json` for security advisories, bloat, copyleft licenses, and lighter alternatives.
3. **💡 Smarter & Lighter Alternatives Advisor**: Automatically recommends modern, lightweight drop-in alternatives for heavy or legacy packages (e.g. suggesting `dayjs` for `moment`, `radash` for `lodash`, or native `fetch` for `request`).
4. **⚖️ Enterprise License Compliance Engine**: Categorizes licenses into Permissive (Commercial Safe), Weak Copyleft (LGPL/MPL), Strong Copyleft (GPL/AGPL), and Unknown/Unlicensed risks.
5. **⏳ Abandonware & Maintenance Vitality**: Flags packages that have had no releases in $>2$ years or suffer from single-maintainer bus factor risk.
6. **🌳 Transitive Dependency Blast Radius**: Reveals hidden dependency trees by comparing direct dependencies against total transitive packages pulled into `node_modules`.
7. **🤖 CI/CD Security Gate & Threshold Policies**: Enforce organizational security and bundle budgets in GitHub Actions with `--fail-under`, `--max-size`, `--no-scripts`, and `--disallow-copyleft` (exits with code `1` on violation).

---

## 🚀 CLI Quick Start

No installation needed — run directly using `npx`:

```bash
# 1. Inspect any package before installing
npx pkg-lens-cli express

# 2. Safely inspect & install with confirmation prompt
npx pkg-lens-cli add express
npx pkg-lens-cli add -D vitest

# 3. Audit entire local project dependencies
npx pkg-lens-cli audit .

# 4. Compare two packages side-by-side
npx pkg-lens-cli moment --vs dayjs
npx pkg-lens-cli express --vs fastify

# 5. Enforce CI/CD security policies (fails build if violated)
npx pkg-lens-cli lodash --fail-under 80 --max-size 30kb

# 6. Export raw JSON for custom pipeline automation
npx pkg-lens-cli axios --json
```

---

## 🛠️ CLI Command Reference

### `pkg-lens-cli <package_name>[@version]`
Inspects registry metadata, security score, CVEs, bundle metrics, license safety, and maintenance health for a package.
```bash
npx pkg-lens-cli react@18.2.0
```

### `pkg-lens-cli add <package_name> [-D] [-y]`
Pre-inspects the target package and displays an interactive prompt asking `? Proceed with npm install [pkg]? [Y/n]`.
* Pass `-D` or `--dev` to install as a devDependency.
* Pass `-y` or `--yes` to bypass prompt confirmation.
```bash
npx pkg-lens-cli add dayjs
npx pkg-lens-cli add typescript -D
```

### `pkg-lens-cli audit [directory_path]`
Audits all dependencies in a `package.json` file concurrently and produces an aggregated project health score and diagnostic table.
```bash
npx pkg-lens-cli audit
npx pkg-lens-cli audit ./backend
```

### `pkg-lens-cli <pkg1> --vs <pkg2>`
Renders a side-by-side comparison matrix highlighting bundle size winners, safety scores, licenses, download popularity, and maintenance vitality.
```bash
npx pkg-lens-cli chalk --vs picocolors
```

---

## 🤖 CI/CD Security Gate Flags

Integrate `pkg-lens-cli` into your GitHub Actions workflow or pre-commit hooks to block pull requests that violate team standards:

| Flag | Description | Example |
| :--- | :--- | :--- |
| `--fail-under <N>` | Fails build (exit code `1`) if Safety Score is below $N/100$ | `--fail-under 80` |
| `--max-size <size>` | Fails build if Gzip size exceeds threshold (`kb`/`mb`) | `--max-size 50kb` |
| `--no-scripts` | Fails build if package defines `preinstall` or `postinstall` hooks | `--no-scripts` |
| `--disallow-copyleft` | Fails build if Strong Copyleft (`GPL`/`AGPL`) license is detected | `--disallow-copyleft` |

#### GitHub Actions Example:
```yaml
- name: Dependency Security Gate
  run: |
    npx pkg-lens-cli express --fail-under 80 --max-size 60kb --no-scripts
```

---

## 📖 Complete Metric Legend

| Metric | Evaluation & Description |
| :--- | :--- |
| **Safety Score** | **100/100 (SAFE)** = Clean audit with zero risk factors.<br>**75-99/100 (MODERATE)** = Minor warnings (single maintainer or stale release).<br>**< 50/100 (CRITICAL)** = Deprecated package, reported CVE vulnerabilities, or dangerous install hooks! |
| **Vulnerabilities (CVE)** | **✅ Clean**: Zero reported OSV vulnerabilities.<br>**⚠️ Advisories**: Real-time GHSA/CVE advisory titles & IDs from Google's OSV.dev database. |
| **Typosquatting Risk** | **⚠️ Possible Typosquat**: Flags package names suspiciously similar to top popular npm targets (e.g. `expresss` vs `express`). |
| **Install Scripts** | **✅ Safe**: No lifecycle execution hooks.<br>**⚠️ Detected Hooks**: Contains `preinstall` or `postinstall` shell commands. |
| **💡 Lighter Alternative** | Recommends modern, lightweight replacements (e.g. `moment` $\rightarrow$ `dayjs`, `uuid` $\rightarrow$ `crypto.randomUUID()`). |
| **Dependencies & Blast** | Displays direct dependencies vs. total transitive dependency footprint and blast radius ratio. |
| **License Compliance** | **Permissive**: `MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC` (Commercial Safe ✅).<br>**Weak Copyleft**: `LGPL`, `MPL` (Commercial Safe with disclosure).<br>**Strong Copyleft**: `GPL`, `AGPL` (Viral open-source risk ⚠️). |
| **Maintenance & Health** | Tracks last publish date, abandonware status ($>2$ years with no release), and single-maintainer bus factor risk. |

---

## 💻 Programmatic API Usage

Use `pkg-lens-cli` as a Node.js library in your custom tooling or build pipelines:

```bash
npm install pkg-lens-cli
```

```javascript
import {
  inspectPackage,
  comparePackages,
  auditProject,
  getAlternativeRecommendation
} from 'pkg-lens-cli';

// 1. Inspect a package programmatically
const reportText = await inspectPackage('express');
console.log(reportText);

// 2. Fetch raw JSON analysis object
const data = await inspectPackage('moment', { json: true });
console.log(`Safety Score: ${data.security.safetyScore}/100`);
console.log(`Lighter Alternative: ${data.alternative?.alternatives.join(', ')}`);
console.log(`Commercial Safe: ${data.license.commercialSafe}`);

// 3. Audit a local repository
const audit = await auditProject('./my-app');
console.log(`Project Health Score: ${audit.overallScore}/100`);
console.log(`Total CVEs: ${audit.totalVulnerabilities}`);

// 4. Compare packages side-by-side
const comparison = await comparePackages('moment', 'dayjs');
console.log(comparison.matrixTable);
```

---

## 📄 License

MIT © [Ujwal Singamsetti](https://github.com/ujwalsingamsetti)
