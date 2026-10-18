#!/usr/bin/env node

/**
 * @file bin/pkg-lens.js
 * Command Line Interface executable for pkg-lens-cli.
 * Supports single inspection, comparison matrix, safe installation guardian (add),
 * local project dependency audit, and CI/CD security gate policy enforcement.
 */

import ora from 'ora';
import pc from 'picocolors';
import {
  inspectPackage,
  comparePackages,
  safeInstallPackage,
  auditProject,
  fetchPackageDetails,
  analyzePackage,
  formatPackageReport
} from '../src/index.js';

const HELP_TEXT = `
${pc.bold(pc.cyan('🔍 PKG-LENS CLI'))} — Pre-install security, bundle footprint & project inspector

${pc.bold('USAGE:')}
  $ npx pkg-lens <package_name>[@version] [options]
  $ npx pkg-lens <package_1> --vs <package_2>
  $ npx pkg-lens add <package_name> [-D] [-y]
  $ npx pkg-lens audit [directory_path]

${pc.bold('COMMANDS:')}
  add <pkg>           Inspect package and prompt to safely install via npm
  audit [dir]         Audit all dependencies in local package.json for risks & bloat

${pc.bold('ARGUMENTS:')}
  <package_name>      NPM package name or specifier (e.g. 'express', 'react@18.2.0')

${pc.bold('OPTIONS & CI/CD POLICIES:')}
  --vs <package_2>    Compare two packages side-by-side (e.g. 'express --vs fastify')
  --json              Output raw JSON analysis object (useful for CI/CD pipelines)
  --fail-under <N>    Exit code 1 if Safety Score is below N (e.g. --fail-under 80)
  --max-size <size>   Exit code 1 if Gzip size exceeds limit (e.g. --max-size 50kb)
  --no-scripts        Exit code 1 if preinstall/postinstall lifecycle hooks exist
  --disallow-copyleft Exit code 1 if Strong Copyleft (GPL/AGPL) license is detected
  -v, --version       Show pkg-lens version
  -h, --help          Show this help message

${pc.bold('EXAMPLES:')}
  $ npx pkg-lens express
  $ npx pkg-lens moment                       # Notice lightweight alternative advice!
  $ npx pkg-lens add axios -D                 # Pre-inspect and prompt to install as devDep
  $ npx pkg-lens audit .                      # Scan entire project dependencies
  $ npx pkg-lens express --vs fastify         # Side-by-side comparison
  $ npx pkg-lens lodash --fail-under 80       # CI/CD security gate check
`;

function parseSizeToBytes(str) {
  if (!str) return null;
  const match = str.trim().toLowerCase().match(/^([0-9.]+)\s*(b|kb|mb|gb)?$/);
  if (!match) return null;
  const num = parseFloat(match[1]);
  const unit = match[2] || 'b';
  const multipliers = { b: 1, kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 };
  return Math.round(num * multipliers[unit]);
}

function evaluateCiPolicy(analysis, policy) {
  const violations = [];
  if (policy.failUnder !== null && analysis.security.safetyScore < policy.failUnder) {
    violations.push(`Safety score (${analysis.security.safetyScore}/100) is below required policy threshold (${policy.failUnder}/100)`);
  }
  if (policy.maxSizeBytes !== null && analysis.footprint.gzippedBytes > policy.maxSizeBytes) {
    violations.push(`Gzip size (${analysis.footprint.gzippedFormatted}) exceeds maximum allowed threshold (${policy.maxSizeRaw})`);
  }
  if (policy.noScripts && analysis.scriptAudit.hasDangerousHooks) {
    violations.push(`Lifecycle script hooks detected (${analysis.scriptAudit.hooks.map((h) => h.name).join(', ')})`);
  }
  if (policy.disallowCopyleft && analysis.license.category === 'STRONG_COPYLEFT') {
    violations.push(`Strong Copyleft license detected (${analysis.license.label})`);
  }
  return violations;
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('pkg-lens-cli v1.2.0');
    process.exit(0);
  }

  const isJson = args.includes('--json');

  // Parse CI policy flags
  const failUnderIdx = args.indexOf('--fail-under');
  const failUnder = failUnderIdx !== -1 ? parseInt(args[failUnderIdx + 1], 10) : null;

  const maxSizeIdx = args.indexOf('--max-size');
  const maxSizeRaw = maxSizeIdx !== -1 ? args[maxSizeIdx + 1] : null;
  const maxSizeBytes = maxSizeRaw ? parseSizeToBytes(maxSizeRaw) : null;

  const noScripts = args.includes('--no-scripts');
  const disallowCopyleft = args.includes('--disallow-copyleft');

  const policy = { failUnder, maxSizeRaw, maxSizeBytes, noScripts, disallowCopyleft };
  const hasPolicy = failUnder !== null || maxSizeBytes !== null || noScripts || disallowCopyleft;

  // 1. Safe Install Guardian: pkg-lens add <pkg>
  if (args[0] === 'add' || args[0] === 'install') {
    const pkgArg = args.find((a, i) => i > 0 && !a.startsWith('-'));
    if (!pkgArg) {
      console.error(pc.red('Error: Please specify a package to install. E.g.: pkg-lens add express'));
      process.exit(1);
    }
    const isDev = args.includes('-D') || args.includes('--save-dev') || args.includes('--dev');
    const isYes = args.includes('-y') || args.includes('--yes');

    try {
      await safeInstallPackage(pkgArg, { dev: isDev, yes: isYes });
      process.exit(0);
    } catch (err) {
      process.exit(1);
    }
  }

  // 2. Project Dependency Audit: pkg-lens audit [dir]
  if (args[0] === 'audit') {
    const targetDir = args.find((a, i) => i > 0 && !a.startsWith('-')) || '.';
    const spinner = isJson ? null : ora(`Auditing dependencies in "${targetDir}"...`).start();

    try {
      const auditResult = await auditProject(targetDir);
      if (spinner) spinner.stop();

      if (isJson) {
        console.log(JSON.stringify(auditResult, null, 2));
      } else {
        console.log(auditResult.reportTable);
      }
      process.exit(0);
    } catch (err) {
      if (spinner) spinner.fail(`Project audit failed: ${err.message}`);
      else console.error(pc.red(`Error: ${err.message}`));
      process.exit(1);
    }
  }

  // 3. Side-by-side comparison mode: pkg-lens <pkg1> --vs <pkg2>
  const vsIdx = args.indexOf('--vs');
  if (vsIdx !== -1) {
    const pkg1 = args[0];
    const pkg2 = args[vsIdx + 1];

    if (!pkg1 || !pkg2 || pkg1.startsWith('-') || pkg2.startsWith('-')) {
      console.error(pc.red('Error: Please provide two valid package names to compare. E.g.: pkg-lens express --vs fastify'));
      process.exit(1);
    }

    const spinner = isJson ? null : ora(`Inspecting and comparing ${pkg1} vs ${pkg2}...`).start();

    try {
      const comparison = await comparePackages(pkg1, pkg2);
      if (spinner) spinner.stop();

      if (isJson) {
        console.log(JSON.stringify(comparison, null, 2));
      } else {
        console.log(comparison.matrixTable);
      }
      process.exit(0);
    } catch (err) {
      if (spinner) spinner.fail(`Comparison failed: ${err.message}`);
      else console.error(pc.red(`Error: ${err.message}`));
      process.exit(1);
    }
  }

  // 4. Single package inspection mode: pkg-lens <package>
  const targetPkg = args.find((a) => !a.startsWith('-'));
  if (!targetPkg) {
    console.error(pc.red('Error: Please specify a package name to inspect. Run `pkg-lens --help` for usage.'));
    process.exit(1);
  }

  const spinner = isJson ? null : ora(`Fetching registry metadata & bundle metrics for "${targetPkg}"...`).start();

  try {
    const rawDetails = await fetchPackageDetails(targetPkg);
    const analysis = analyzePackage(rawDetails);
    if (spinner) spinner.stop();

    if (isJson) {
      console.log(JSON.stringify(analysis, null, 2));
    } else {
      console.log(formatPackageReport(analysis));
    }

    // Check CI/CD Policy Rules
    if (hasPolicy) {
      const violations = evaluateCiPolicy(analysis, policy);
      if (violations.length > 0) {
        console.error(pc.bold(pc.red('\n❌ CI/CD SECURITY POLICY FAILED:')));
        for (const v of violations) {
          console.error(pc.red(`  • ${v}`));
        }
        console.error('');
        process.exit(1);
      } else {
        console.log(pc.bold(pc.green('✅ CI/CD Security Policy Passed! All threshold checks satisfied.\n')));
      }
    }

    process.exit(0);
  } catch (err) {
    if (spinner) spinner.fail(`Failed to inspect package "${targetPkg}": ${err.message}`);
    else console.error(pc.red(`Error: ${err.message}`));
    process.exit(1);
  }
}

main();
