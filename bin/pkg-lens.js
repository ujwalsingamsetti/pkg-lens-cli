#!/usr/bin/env node

/**
 * @file bin/pkg-lens.js
 * Command Line Interface executable for pkg-lens.
 */

import ora from 'ora';
import pc from 'picocolors';
import { inspectPackage, comparePackages } from '../src/index.js';

const HELP_TEXT = `
${pc.bold(pc.cyan('🔍 PKG-LENS CLI'))} — Pre-install security & bundle footprint inspector

${pc.bold('USAGE:')}
  $ npx pkg-lens <package_name>[@version] [options]
  $ npx pkg-lens <package_1> --vs <package_2>

${pc.bold('ARGUMENTS:')}
  <package_name>      NPM package name or specifier (e.g. 'express', 'react@18.2.0', '@types/node')

${pc.bold('OPTIONS:')}
  --vs <package_2>    Compare two packages side-by-side (e.g. 'express --vs fastify')
  --json              Output raw JSON analysis object (useful for CI/CD pipelines)
  -v, --version       Show pkg-lens version
  -h, --help          Show this help message

${pc.bold('EXAMPLES:')}
  $ npx pkg-lens express
  $ npx pkg-lens react@18.2.0
  $ npx pkg-lens express --vs fastify
  $ npx pkg-lens lodash --json
`;

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('pkg-lens-cli v1.0.0');
    process.exit(0);
  }

  const isJson = args.includes('--json');
  const vsIdx = args.indexOf('--vs');

  // Side-by-side comparison mode
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

  // Single package inspection mode
  const targetPkg = args.find((a) => !a.startsWith('-'));
  if (!targetPkg) {
    console.error(pc.red('Error: Please specify a package name to inspect. Run `pkg-lens --help` for usage.'));
    process.exit(1);
  }

  const spinner = isJson ? null : ora(`Fetching registry metadata & bundle metrics for "${targetPkg}"...`).start();

  try {
    const result = await inspectPackage(targetPkg, { json: isJson });
    if (spinner) spinner.stop();

    if (isJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(result);
    }
    process.exit(0);
  } catch (err) {
    if (spinner) spinner.fail(`Failed to inspect package "${targetPkg}": ${err.message}`);
    else console.error(pc.red(`Error: ${err.message}`));
    process.exit(1);
  }
}

main();
