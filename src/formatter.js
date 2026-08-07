/**
 * @file formatter.js
 * Terminal report renderer utilizing picocolors and cli-table3
 * for clean visual presentations, badges, and alerts.
 */

import pc from 'picocolors';
import Table from 'cli-table3';

/**
 * Format large numbers with commas (e.g., 1,234,567)
 * @param {number} num
 * @returns {string}
 */
function formatNumber(num) {
  if (num === null || num === undefined || isNaN(num)) return '0';
  return num.toLocaleString('en-US');
}

/**
 * Create a colored badge string for risk levels.
 * @param {string} level - 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL'
 * @returns {string} Styled badge text
 */
function renderRiskBadge(level) {
  switch (level) {
    case 'LOW':
      return pc.bgGreen(pc.black(` SAFE (LOW RISK) `));
    case 'MODERATE':
      return pc.bgYellow(pc.black(` MODERATE RISK `));
    case 'HIGH':
      return pc.bgRed(pc.white(` HIGH RISK `));
    case 'CRITICAL':
      return pc.bgMagenta(pc.white(` CRITICAL RISK `));
    default:
      return pc.bgGray(pc.white(` ${level} `));
  }
}

/**
 * Render visual progress gauge bar for safety score [██████░░░░]
 * @param {number} safetyScore - 0 to 100 (100 = perfectly safe)
 * @returns {string}
 */
function renderProgressBar(safetyScore) {
  const totalBlocks = 15;
  const filledBlocks = Math.round((safetyScore / 100) * totalBlocks);
  const emptyBlocks = totalBlocks - filledBlocks;
  const filledStr = '█'.repeat(filledBlocks);
  const emptyStr = '░'.repeat(emptyBlocks);

  let coloredGauge = filledStr;
  if (safetyScore >= 75) coloredGauge = pc.green(filledStr);
  else if (safetyScore >= 50) coloredGauge = pc.yellow(filledStr);
  else if (safetyScore >= 25) coloredGauge = pc.red(filledStr);
  else coloredGauge = pc.magenta(filledStr);

  return `[${coloredGauge}${pc.dim(emptyStr)}] ${safetyScore}/100`;
}

/**
 * Main report renderer function.
 * @param {object} analysis - Object returned from analyzePackage()
 * @returns {string} Formatted ANSI terminal string
 */
export function formatPackageReport(analysis) {
  const lines = [];

  // Header Banner
  lines.push('');
  lines.push(pc.bold(pc.cyan(` 🔍 PKG-LENS REPORT `)) + ` — ` + pc.bold(pc.white(`${analysis.name}@${analysis.version}`)));
  lines.push(pc.dim(` ${analysis.description}`));
  lines.push('');

  // Overview Table
  const table = new Table({
    head: [pc.bold(pc.cyan('Metric')), pc.bold(pc.cyan('Evaluation & Details'))],
    colWidths: [22, 60],
    wordWrap: true
  });

  // 1. Security & Safety
  const riskBadge = renderRiskBadge(analysis.security.level);
  const progressBar = renderProgressBar(analysis.security.safetyScore);
  table.push([
    pc.bold('Safety Score'),
    `${riskBadge}  ${progressBar}`
  ]);

  // Deprecated flag warning
  if (analysis.deprecated) {
    table.push([
      pc.bold(pc.red('Deprecation Warning')),
      pc.red(`⚠️ DEPRECATED: ${analysis.deprecated}`)
    ]);
  }

  // 2. Lifecycle Scripts Audit
  if (analysis.scriptAudit.hasDangerousHooks) {
    const hookDetails = analysis.scriptAudit.hooks
      .map((h) => pc.red(`• ${h.name}: `) + pc.yellow(`"${h.command}"`))
      .join('\n');
    table.push([
      pc.bold(pc.red('Install Scripts')),
      pc.bold(pc.red(`⚠️ DETECTED ${analysis.scriptAudit.hooks.length} LIFECYCLE HOOK(S):\n`)) + hookDetails
    ]);
  } else {
    table.push([
      pc.bold('Install Scripts'),
      pc.green('✅ Safe (No preinstall/postinstall hooks detected)')
    ]);
  }

  // 3. Bundle Footprint
  const treeShakeText = analysis.footprint.isTreeShakeable
    ? pc.green('Yes ✅ (ESM / Side-effect free)')
    : pc.dim('No / Unknown ⚠️');

  table.push([
    pc.bold('Bundle Size (Gzip)'),
    `${pc.bold(pc.yellow(analysis.footprint.gzippedFormatted))} ${pc.dim(`(Minified: ${analysis.footprint.minifiedFormatted})`)}`
  ]);

  table.push([
    pc.bold('Tree-Shakeable'),
    treeShakeText
  ]);

  // 4. Dependencies
  table.push([
    pc.bold('Dependencies'),
    `${pc.cyan(analysis.footprint.directDependenciesCount)} direct / ~${pc.cyan(analysis.footprint.totalDependenciesCount)} total`
  ]);

  // 5. License
  let licenseColor = pc.green;
  if (analysis.license.riskLevel === 'HIGH') licenseColor = pc.red;
  else if (analysis.license.riskLevel === 'MODERATE') licenseColor = pc.yellow;

  table.push([
    pc.bold('License Safety'),
    licenseColor(`${analysis.license.label} (${analysis.license.category})`)
  ]);

  // 6. Community & Maintainability
  const formattedRelease = analysis.releaseDate
    ? analysis.releaseDate.toISOString().split('T')[0]
    : 'Unknown';

  table.push([
    pc.bold('Downloads (Weekly)'),
    `${pc.bold(formatNumber(analysis.downloadsWeekly))} / week`
  ]);

  table.push([
    pc.bold('Maintainers & Release'),
    `${analysis.maintainersCount} maintainer(s) • Last release: ${formattedRelease}`
  ]);

  lines.push(table.toString());

  // Risk Factors Summary callout box (if any)
  if (analysis.security.riskFactors.length > 0) {
    lines.push('');
    lines.push(pc.bold(pc.yellow(' ⚠️ RISK FACTORS & ALERT SUMMARY:')));
    for (const factor of analysis.security.riskFactors) {
      lines.push(`   ${pc.yellow('•')} ${factor}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}
