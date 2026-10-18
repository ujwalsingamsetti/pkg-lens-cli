/**
 * @file auditor.js
 * Local Project Dependency Auditor.
 * Scans a project's package.json to identify security vulnerabilities,
 * bundle bloat, copyleft licenses, install scripts, and modern alternatives.
 */

import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import Table from 'cli-table3';
import { fetchPackageDetails } from './fetcher.js';
import { analyzePackage } from './analyzer.js';

/**
 * Concurrency helper to run promises with a concurrency limit
 */
async function mapConcurrent(items, limit, fn) {
  const results = new Array(items.length);
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const i = index++;
      try {
        results[i] = await fn(items[i], i);
      } catch (err) {
        results[i] = { error: err.message, name: items[i] };
      }
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Audit a project's package.json dependencies
 * @param {string} [dir='.'] - Directory containing package.json
 * @param {object} [options]
 * @param {boolean} [options.dev=true] - Include devDependencies
 * @returns {Promise<object>} Project audit report
 */
export async function auditProject(dir = '.', options = {}) {
  const resolvedDir = path.resolve(process.cwd(), dir);
  const pkgJsonPath = path.join(resolvedDir, 'package.json');

  if (!fs.existsSync(pkgJsonPath)) {
    throw new Error(`No package.json found at "${pkgJsonPath}"`);
  }

  const rawJson = fs.readFileSync(pkgJsonPath, 'utf8');
  let pkgData;
  try {
    pkgData = JSON.parse(rawJson);
  } catch (err) {
    throw new Error(`Failed to parse package.json: ${err.message}`);
  }

  const prodDeps = Object.keys(pkgData.dependencies || {});
  const devDeps = options.dev !== false ? Object.keys(pkgData.devDependencies || {}) : [];
  const allDeps = [...new Set([...prodDeps, ...devDeps])];

  if (allDeps.length === 0) {
    return {
      projectName: pkgData.name || 'unnamed-project',
      projectVersion: pkgData.version || '0.0.0',
      totalDependencies: 0,
      overallScore: 100,
      results: [],
      reportTable: pc.green('\n✅ No dependencies found in package.json to audit.\n')
    };
  }

  // Scan dependencies concurrently in batches of 4
  const analyzed = await mapConcurrent(allDeps, 4, async (depName) => {
    try {
      const details = await fetchPackageDetails(depName);
      return analyzePackage(details);
    } catch (err) {
      return {
        name: depName,
        failed: true,
        error: err.message,
        security: { safetyScore: 50, level: 'MODERATE' },
        vulnerabilities: [],
        footprint: { gzippedFormatted: 'N/A', gzippedBytes: 0 },
        license: { label: 'UNKNOWN', category: 'UNKNOWN', commercialSafe: false },
        scriptAudit: { hasDangerousHooks: false },
        alternative: null
      };
    }
  });

  // Calculate project aggregates
  let totalScore = 0;
  let totalVulns = 0;
  let hookPackagesCount = 0;
  let copyleftCount = 0;
  let totalGzipBytes = 0;
  const suggestedAlternatives = [];

  for (const item of analyzed) {
    if (item.failed) continue;
    totalScore += item.security.safetyScore;
    totalVulns += item.vulnerabilities.length;
    if (item.scriptAudit.hasDangerousHooks) hookPackagesCount++;
    if (item.license.category === 'STRONG_COPYLEFT') copyleftCount++;
    totalGzipBytes += item.footprint.gzippedBytes;
    if (item.alternative) {
      suggestedAlternatives.push({
        pkg: item.name,
        alternatives: item.alternative.alternatives,
        savings: item.alternative.savings
      });
    }
  }

  const validCount = analyzed.filter((a) => !a.failed).length || 1;
  const averageSafetyScore = Math.round(totalScore / validCount);

  // Generate output table
  const table = new Table({
    head: [
      pc.bold(pc.cyan('Package')),
      pc.bold(pc.cyan('Safety')),
      pc.bold(pc.cyan('CVEs')),
      pc.bold(pc.cyan('License')),
      pc.bold(pc.cyan('Gzip Size')),
      pc.bold(pc.cyan('Hooks')),
      pc.bold(pc.cyan('Notes & Alternatives'))
    ],
    colWidths: [18, 10, 8, 14, 12, 9, 28],
    wordWrap: true
  });

  // Sort: highest risk packages first
  analyzed.sort((a, b) => (a.security.safetyScore || 0) - (b.security.safetyScore || 0));

  for (const item of analyzed) {
    let scoreDisplay = pc.green(`${item.security.safetyScore}/100`);
    if (item.security.safetyScore < 50) scoreDisplay = pc.red(`${item.security.safetyScore}/100`);
    else if (item.security.safetyScore < 75) scoreDisplay = pc.yellow(`${item.security.safetyScore}/100`);

    const cveDisplay = item.vulnerabilities.length > 0
      ? pc.red(`${item.vulnerabilities.length} ⚠️`)
      : pc.green('0');

    let licDisplay = pc.green(item.license.label);
    if (item.license.category === 'STRONG_COPYLEFT') licDisplay = pc.red(item.license.label);
    else if (item.license.category === 'UNKNOWN') licDisplay = pc.yellow(item.license.label);

    const hookDisplay = item.scriptAudit.hasDangerousHooks ? pc.red('YES ⚠️') : pc.green('None');

    let notes = '';
    if (item.alternative) {
      notes = pc.magenta(`💡 Try: ${item.alternative.alternatives[0]}`);
    } else if (item.vulnerabilities.length > 0) {
      notes = pc.red(`Advisory: ${item.vulnerabilities[0].id}`);
    } else if (item.license.category === 'STRONG_COPYLEFT') {
      notes = pc.red('Copyleft risk');
    } else {
      notes = pc.dim('OK');
    }

    table.push([
      pc.bold(item.name),
      scoreDisplay,
      cveDisplay,
      licDisplay,
      item.footprint.gzippedFormatted || 'N/A',
      hookDisplay,
      notes
    ]);
  }

  const out = [];
  out.push('');
  out.push(pc.bold(pc.cyan(' 📊 PKG-LENS PROJECT DEPENDENCY AUDIT')));
  out.push(pc.dim(` Project: ${pkgData.name || 'unnamed'}@${pkgData.version || '0.0.0'} (${allDeps.length} dependencies)`));
  out.push('');
  out.push(table.toString());
  out.push('');

  // Summary Card
  const summaryTable = new Table({
    head: [pc.bold(pc.cyan('Project Metric')), pc.bold(pc.cyan('Audit Assessment'))],
    colWidths: [26, 52]
  });

  let healthColor = pc.green;
  if (averageSafetyScore < 50) healthColor = pc.red;
  else if (averageSafetyScore < 75) healthColor = pc.yellow;

  summaryTable.push([
    pc.bold('Project Health Score'),
    healthColor(pc.bold(`${averageSafetyScore}/100`))
  ]);

  summaryTable.push([
    pc.bold('Security CVE Vulnerabilities'),
    totalVulns > 0 ? pc.red(`⚠️ ${totalVulns} vulnerability advisory(ies) found`) : pc.green('✅ Clean (0 vulnerabilities)')
  ]);

  summaryTable.push([
    pc.bold('Install Lifecycle Hooks'),
    hookPackagesCount > 0 ? pc.red(`⚠️ ${hookPackagesCount} package(s) have pre/postinstall hooks`) : pc.green('✅ Safe (0 hook scripts)')
  ]);

  summaryTable.push([
    pc.bold('Copyleft Legal Risk'),
    copyleftCount > 0 ? pc.red(`⚠️ ${copyleftCount} strong copyleft license(s) detected`) : pc.green('✅ Permissive / Commercial Safe')
  ]);

  if (suggestedAlternatives.length > 0) {
    const altText = suggestedAlternatives
      .map((a) => `${pc.bold(a.pkg)} ➔ ${pc.magenta(a.alternatives.join(', '))} (${a.savings || 'lighter'})`)
      .join('\n');
    summaryTable.push([
      pc.bold(pc.magenta('Lighter Alternative Suggestions')),
      altText
    ]);
  }

  out.push(summaryTable.toString());
  out.push('');

  return {
    projectName: pkgData.name,
    projectVersion: pkgData.version,
    totalDependencies: allDeps.length,
    overallScore: averageSafetyScore,
    totalVulnerabilities: totalVulns,
    hookPackagesCount,
    copyleftCount,
    suggestedAlternatives,
    reportTable: out.join('\n'),
    analyzed
  };
}
