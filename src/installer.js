/**
 * @file installer.js
 * Safe package installation wrapper.
 * Inspects package security, license, scripts, and footprint BEFORE
 * prompting the user and running `npm install`.
 */

import readline from 'node:readline';
import { spawn } from 'node:child_process';
import pc from 'picocolors';
import ora from 'ora';
import Table from 'cli-table3';
import { fetchPackageDetails } from './fetcher.js';
import { analyzePackage } from './analyzer.js';

function promptUser(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function renderMiniScorecard(analysis, isDev) {
  const table = new Table({
    head: [pc.bold(pc.cyan('Metric')), pc.bold(pc.cyan('Inspection Result'))],
    colWidths: [22, 58],
    wordWrap: true
  });

  // Safety Score
  let scoreBadge = pc.bgGreen(pc.black(` SAFE `));
  if (analysis.security.level === 'MODERATE') scoreBadge = pc.bgYellow(pc.black(` MODERATE RISK `));
  else if (analysis.security.level === 'HIGH') scoreBadge = pc.bgRed(pc.white(` HIGH RISK `));
  else if (analysis.security.level === 'CRITICAL') scoreBadge = pc.bgMagenta(pc.white(` CRITICAL RISK `));

  table.push([
    pc.bold('Safety Score'),
    `${scoreBadge} ${analysis.security.safetyScore}/100 (${analysis.security.level} RISK)`
  ]);

  // CVEs
  if (analysis.vulnerabilities.length > 0) {
    table.push([
      pc.bold(pc.red('Vulnerabilities')),
      pc.red(`⚠️ ${analysis.vulnerabilities.length} CVE security advisories detected!`)
    ]);
  } else {
    table.push([pc.bold('Vulnerabilities'), pc.green('✅ Clean (0 reported CVEs)')]);
  }

  // Typosquatting
  if (analysis.typosquat?.isTyposquat) {
    table.push([
      pc.bold(pc.red('Typosquatting')),
      pc.red(`⚠️ Suspected clone of popular package "${analysis.typosquat.similarTo}"!`)
    ]);
  }

  // Install scripts
  if (analysis.scriptAudit.hasDangerousHooks) {
    table.push([
      pc.bold(pc.red('Install Scripts')),
      pc.red(`⚠️ Contains lifecycle hooks: ${analysis.scriptAudit.hooks.map((h) => h.name).join(', ')}`)
    ]);
  } else {
    table.push([pc.bold('Install Scripts'), pc.green('✅ None (No auto-executing scripts)')]);
  }

  // License
  let licColor = pc.green;
  if (analysis.license.riskLevel === 'HIGH') licColor = pc.red;
  else if (analysis.license.riskLevel === 'MODERATE') licColor = pc.yellow;
  table.push([
    pc.bold('License Safety'),
    licColor(`${analysis.license.label} — ${analysis.license.commercialSafe ? 'Commercial Safe ✅' : 'High Legal Risk ⚠️'}`)
  ]);

  // Bundle footprint
  table.push([
    pc.bold('Bundle Size'),
    `${pc.yellow(analysis.footprint.gzippedFormatted)} gzip (${analysis.footprint.minifiedFormatted} minified)`
  ]);

  // Alternatives
  if (analysis.alternative) {
    table.push([
      pc.bold(pc.magenta('💡 Lighter Alternative')),
      pc.magenta(`Consider: ${analysis.alternative.alternatives.join(', ')} (${analysis.alternative.savings || 'faster'})`)
    ]);
  }

  const out = [];
  out.push('');
  out.push(pc.bold(pc.cyan('🛡️  PKG-LENS PRE-INSTALL GUARDIAN')));
  out.push(pc.dim(` Inspecting ${analysis.name}@${analysis.version} before installing...`));
  out.push('');
  out.push(table.toString());
  out.push('');

  return out.join('\n');
}

/**
 * Perform a safe package installation
 * @param {string} specifier - E.g. 'express' or 'express@4.18.2'
 * @param {object} [options]
 * @param {boolean} [options.dev=false] - Install as devDependency (-D)
 * @param {boolean} [options.yes=false] - Bypass prompt and install immediately
 */
export async function safeInstallPackage(specifier, options = {}) {
  const spinner = ora(`Inspecting "${specifier}" before installation...`).start();

  let analysis;
  try {
    const rawDetails = await fetchPackageDetails(specifier);
    analysis = analyzePackage(rawDetails);
    spinner.stop();
  } catch (err) {
    spinner.fail(`Failed to inspect package "${specifier}": ${err.message}`);
    process.exit(1);
  }

  console.log(renderMiniScorecard(analysis, options.dev));

  // Determine install command
  const isDev = Boolean(options.dev);
  const installCmd = `npm install ${isDev ? '-D ' : ''}${specifier}`;

  if (!options.yes) {
    const defaultChoice = analysis.security.safetyScore >= 50 ? 'Y/n' : 'y/N';
    const answer = await promptUser(pc.bold(`? Proceed with \`${installCmd}\`? [${defaultChoice}]: `));
    const normalized = answer.toLowerCase();

    const proceed = analysis.security.safetyScore >= 50
      ? (normalized === '' || normalized === 'y' || normalized === 'yes')
      : (normalized === 'y' || normalized === 'yes');

    if (!proceed) {
      console.log(pc.yellow('\n✖ Installation aborted by user. No packages were installed.\n'));
      return { installed: false, analysis };
    }
  }

  console.log(pc.cyan(`\n🚀 Executing: ${pc.bold(installCmd)}...\n`));

  return new Promise((resolve, reject) => {
    const args = ['install'];
    if (isDev) args.push('-D');
    args.push(specifier);

    const child = spawn('npm', args, { stdio: 'inherit', shell: true });

    child.on('close', (code) => {
      if (code === 0) {
        console.log(pc.green(`\n✅ Successfully installed ${specifier}!\n`));
        resolve({ installed: true, analysis });
      } else {
        console.error(pc.red(`\n❌ npm install exited with code ${code}\n`));
        reject(new Error(`npm install failed with exit code ${code}`));
      }
    });

    child.on('error', (err) => {
      console.error(pc.red(`Failed to spawn npm: ${err.message}`));
      reject(err);
    });
  });
}
