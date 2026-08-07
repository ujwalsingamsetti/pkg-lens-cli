/**
 * @file comparator.js
 * Side-by-side comparison engine and matrix formatter for comparing two npm packages.
 */

import pc from 'picocolors';
import Table from 'cli-table3';
import { fetchPackageDetails } from './fetcher.js';
import { analyzePackage } from './analyzer.js';
import { formatBytes } from './analyzer.js';

/**
 * Compare two npm packages side-by-side.
 * @param {string} spec1 - First package specifier (e.g. 'express')
 * @param {string} spec2 - Second package specifier (e.g. 'fastify')
 * @returns {Promise<{ pkg1: object, pkg2: object, matrixTable: string }>}
 */
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
  table.push([
    pc.bold('Safety Score'),
    `${a1.security.safetyScore}/100 (${a1.security.level === 'LOW' ? 'SAFE' : a1.security.level})`,
    `${a2.security.safetyScore}/100 (${a2.security.level === 'LOW' ? 'SAFE' : a2.security.level})`
  ]);

  // Gzip Bundle Size
  const size1 = a1.footprint.gzippedBytes;
  const size2 = a2.footprint.gzippedBytes;

  let sizeStr1 = a1.footprint.gzippedFormatted;
  let sizeStr2 = a2.footprint.gzippedFormatted;

  if (size1 > 0 && size2 > 0) {
    if (size1 < size2) {
      sizeStr1 = pc.green(`${sizeStr1} 👑 (Smaller)`);
    } else if (size2 < size1) {
      sizeStr2 = pc.green(`${sizeStr2} 👑 (Smaller)`);
    }
  }

  table.push([pc.bold('Gzip Bundle Size'), sizeStr1, sizeStr2]);

  // Tree Shakeable
  table.push([
    pc.bold('Tree-Shakeable'),
    a1.footprint.isTreeShakeable ? pc.green('Yes ✅') : pc.dim('No ⚠️'),
    a2.footprint.isTreeShakeable ? pc.green('Yes ✅') : pc.dim('No ⚠️')
  ]);

  // Dependencies
  table.push([
    pc.bold('Dependencies (Direct)'),
    `${a1.footprint.directDependenciesCount} deps`,
    `${a2.footprint.directDependenciesCount} deps`
  ]);

  // License
  table.push([
    pc.bold('License'),
    a1.license.label,
    a2.license.label
  ]);

  // Weekly Downloads
  table.push([
    pc.bold('Weekly Downloads'),
    a1.downloadsWeekly.toLocaleString(),
    a2.downloadsWeekly.toLocaleString()
  ]);

  // Install Scripts
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

  return {
    pkg1: a1,
    pkg2: a2,
    matrixTable: output.join('\n')
  };
}
