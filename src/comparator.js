/**
 * @file comparator.js
 * Side-by-side comparison matrix renderer for comparing two npm packages.
 */

import pc from 'picocolors';
import Table from 'cli-table3';
import { fetchPackageDetails } from './fetcher.js';
import { analyzePackage } from './analyzer.js';

export async function comparePackages(spec1, spec2) {
  const [details1, details2] = await Promise.all([
    fetchPackageDetails(spec1),
    fetchPackageDetails(spec2)
  ]);

  const a1 = analyzePackage(details1);
  const a2 = analyzePackage(details2);

  const table = new Table({
    head: [
      pc.bold(pc.cyan('Feature / Metric')),
      pc.bold(pc.white(`${a1.name}@${a1.version}`)),
      pc.bold(pc.white(`${a2.name}@${a2.version}`))
    ],
    colWidths: [22, 33, 33],
    wordWrap: true
  });

  // Safety Score
  let score1 = `${a1.security.safetyScore}/100`;
  let score2 = `${a2.security.safetyScore}/100`;
  if (a1.security.safetyScore > a2.security.safetyScore) score1 = pc.green(`${score1} 👑 (Safer)`);
  else if (a2.security.safetyScore > a1.security.safetyScore) score2 = pc.green(`${score2} 👑 (Safer)`);

  table.push([
    pc.bold('Safety Score'),
    `${score1} (${a1.security.level})`,
    `${score2} (${a2.security.level})`
  ]);

  // Vulnerabilities (CVE)
  table.push([
    pc.bold('Vulnerabilities (CVE)'),
    a1.vulnerabilities.length > 0 ? pc.red(`⚠️ ${a1.vulnerabilities.length} Advisory(ies)`) : pc.green('Clean ✅'),
    a2.vulnerabilities.length > 0 ? pc.red(`⚠️ ${a2.vulnerabilities.length} Advisory(ies)`) : pc.green('Clean ✅')
  ]);

  // Gzip Bundle Size
  const size1 = a1.footprint.gzippedBytes;
  const size2 = a2.footprint.gzippedBytes;
  let sizeStr1 = a1.footprint.gzippedFormatted;
  let sizeStr2 = a2.footprint.gzippedFormatted;

  if (size1 > 0 && size2 > 0) {
    if (size1 < size2) sizeStr1 = pc.green(`${sizeStr1} 👑 (Smaller)`);
    else if (size2 < size1) sizeStr2 = pc.green(`${sizeStr2} 👑 (Smaller)`);
  }

  table.push([pc.bold('Gzip Bundle Size'), sizeStr1, sizeStr2]);

  // Tree-Shakeable
  table.push([
    pc.bold('Tree-Shakeable'),
    a1.footprint.isTreeShakeable ? pc.green('Yes ✅') : pc.dim('No ⚠️'),
    a2.footprint.isTreeShakeable ? pc.green('Yes ✅') : pc.dim('No ⚠️')
  ]);

  // Dependencies & Blast Radius
  table.push([
    pc.bold('Dependencies & Blast'),
    `${a1.footprint.directDependenciesCount} direct / ~${a1.footprint.totalDependenciesCount} total`,
    `${a2.footprint.directDependenciesCount} direct / ~${a2.footprint.totalDependenciesCount} total`
  ]);

  // License & Commercial Safety
  const licStr1 = `${a1.license.label} (${a1.license.commercialSafe ? 'Safe ✅' : 'Copyleft ⚠️'})`;
  const licStr2 = `${a2.license.label} (${a2.license.commercialSafe ? 'Safe ✅' : 'Copyleft ⚠️'})`;
  table.push([
    pc.bold('License Compliance'),
    a1.license.commercialSafe ? pc.green(licStr1) : pc.red(licStr1),
    a2.license.commercialSafe ? pc.green(licStr2) : pc.red(licStr2)
  ]);

  // Weekly Downloads
  let dlStr1 = a1.downloadsWeekly.toLocaleString();
  let dlStr2 = a2.downloadsWeekly.toLocaleString();
  if (a1.downloadsWeekly > a2.downloadsWeekly) dlStr1 = pc.green(`${dlStr1} 👑`);
  else if (a2.downloadsWeekly > a1.downloadsWeekly) dlStr2 = pc.green(`${dlStr2} 👑`);
  table.push([pc.bold('Weekly Downloads'), dlStr1, dlStr2]);

  // Maintenance & Abandonware
  const m1 = a1.maintenance.isAbandoned ? pc.red('Abandoned (>2y) ⚠️') : (a1.maintenance.isStale ? pc.yellow('Stale (>1y) ⚠️') : pc.green('Active ✅'));
  const m2 = a2.maintenance.isAbandoned ? pc.red('Abandoned (>2y) ⚠️') : (a2.maintenance.isStale ? pc.yellow('Stale (>1y) ⚠️') : pc.green('Active ✅'));
  table.push([pc.bold('Maintenance'), m1, m2]);

  // Lifecycle Scripts
  table.push([
    pc.bold('Lifecycle Scripts'),
    a1.scriptAudit.hasDangerousHooks ? pc.red(`⚠️ ${a1.scriptAudit.hooks.length} Hooks`) : pc.green('Safe ✅'),
    a2.scriptAudit.hasDangerousHooks ? pc.red(`⚠️ ${a2.scriptAudit.hooks.length} Hooks`) : pc.green('Safe ✅')
  ]);

  const output = [];
  output.push('');
  output.push(pc.bold(pc.cyan(` ⚔️ PKG-LENS COMPARISON MATRIX `)));
  output.push(pc.dim(` Comparing ${a1.name} vs ${a2.name}`));
  output.push('');
  output.push(table.toString());
  output.push('');

  return { pkg1: a1, pkg2: a2, matrixTable: output.join('\n') };
}
