/**
 * @file formatter.js
 * Terminal report renderer utilizing picocolors and cli-table3
 * with OSV vulnerability advisories and typosquatting alerts.
 */

import pc from 'picocolors';
import Table from 'cli-table3';

function formatNumber(num) {
  if (num === null || num === undefined || isNaN(num)) return '0';
  return num.toLocaleString('en-US');
}

function renderRiskBadge(level) {
  switch (level) {
    case 'LOW': return pc.bgGreen(pc.black(` SAFE (LOW RISK) `));
    case 'MODERATE': return pc.bgYellow(pc.black(` MODERATE RISK `));
    case 'HIGH': return pc.bgRed(pc.white(` HIGH RISK `));
    case 'CRITICAL': return pc.bgMagenta(pc.white(` CRITICAL RISK `));
    default: return pc.bgGray(pc.white(` ${level} `));
  }
}

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

export function formatPackageReport(analysis) {
  const lines = [];

  lines.push('');
  lines.push(pc.bold(pc.cyan(` 🔍 PKG-LENS REPORT `)) + ` — ` + pc.bold(pc.white(`${analysis.name}@${analysis.version}`)));
  lines.push(pc.dim(` ${analysis.description}`));
  lines.push('');

  const table = new Table({
    head: [pc.bold(pc.cyan('Metric')), pc.bold(pc.cyan('Evaluation & Details'))],
    colWidths: [22, 60],
    wordWrap: true
  });

  const riskBadge = renderRiskBadge(analysis.security.level);
  const progressBar = renderProgressBar(analysis.security.safetyScore);
  table.push([
    pc.bold('Safety Score'),
    `${riskBadge}  ${progressBar}`
  ]);

  // OSV Vulnerability Advisories
  if (analysis.vulnerabilities.length > 0) {
    const vulnSummary = analysis.vulnerabilities
      .map((v) => pc.red(`• ${v.id}: `) + pc.yellow(v.summary))
      .join('\n');
    table.push([
      pc.bold(pc.red('Vulnerabilities (CVE)')),
      pc.bold(pc.red(`⚠️ DETECTED ${analysis.vulnerabilities.length} ADVISORY(IES):\n`)) + vulnSummary
    ]);
  } else {
    table.push([
      pc.bold('Vulnerabilities (CVE)'),
      pc.green('✅ Clean (0 reported OSV vulnerabilities)')
    ]);
  }

  // Typosquatting alert
  if (analysis.typosquat?.isTyposquat) {
    table.push([
      pc.bold(pc.red('Typosquatting Risk')),
      pc.red(`⚠️ POSSIBLE TYPOSQUAT: Similar to popular package "${analysis.typosquat.similarTo}"`)
    ]);
  }

  if (analysis.deprecated) {
    table.push([
      pc.bold(pc.red('Deprecation Warning')),
      pc.red(`⚠️ DEPRECATED: ${analysis.deprecated}`)
    ]);
  }

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

  table.push([
    pc.bold('Dependencies'),
    `${pc.cyan(analysis.footprint.directDependenciesCount)} direct / ~${pc.cyan(analysis.footprint.totalDependenciesCount)} total`
  ]);

  let licenseColor = pc.green;
  if (analysis.license.riskLevel === 'HIGH') licenseColor = pc.red;
  else if (analysis.license.riskLevel === 'MODERATE') licenseColor = pc.yellow;

  table.push([
    pc.bold('License Safety'),
    licenseColor(`${analysis.license.label} (${analysis.license.category})`)
  ]);

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
