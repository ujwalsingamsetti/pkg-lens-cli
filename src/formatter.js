/**
 * @file formatter.js
 * Terminal report renderer utilizing picocolors and cli-table3
 * with OSV vulnerability advisories, typosquatting alerts, license compliance,
 * maintenance health, dependency blast radius, and alternative recommendations.
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

  // Deprecation Warning
  if (analysis.deprecated) {
    table.push([
      pc.bold(pc.red('Deprecation Warning')),
      pc.red(`⚠️ DEPRECATED: ${analysis.deprecated}`)
    ]);
  }

  // Install Scripts
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

  // Smarter Alternatives Recommendation
  if (analysis.alternative) {
    table.push([
      pc.bold(pc.magenta('💡 Lighter Alternative')),
      pc.bold(pc.magenta(`Consider: ${analysis.alternative.alternatives.join(', ')}\n`)) +
      pc.dim(`${analysis.alternative.reason}\nSavings: ${analysis.alternative.savings || 'reduced bundle footprint'}`)
    ]);
  }

  // Bundle Footprint
  table.push([
    pc.bold('Bundle Size (Gzip)'),
    `${pc.bold(pc.yellow(analysis.footprint.gzippedFormatted))} ${pc.dim(`(Minified: ${analysis.footprint.minifiedFormatted})`)}`
  ]);

  // Tree-Shakeable
  const treeShakeText = analysis.footprint.isTreeShakeable
    ? pc.green('Yes ✅ (ESM / Side-effect free)')
    : pc.dim('No / Unknown ⚠️');
  table.push([
    pc.bold('Tree-Shakeable'),
    treeShakeText
  ]);

  // Dependency Blast Radius
  let blastNote = '';
  if (analysis.footprint.isHighBlastRadius) {
    blastNote = pc.red(`\n⚠️ HIGH BLAST RADIUS: Brings ${analysis.footprint.transitiveDependenciesCount} transitive dependencies!`);
  }
  table.push([
    pc.bold('Dependencies & Blast'),
    `${pc.cyan(analysis.footprint.directDependenciesCount)} direct / ~${pc.cyan(analysis.footprint.totalDependenciesCount)} total (${pc.dim(analysis.footprint.blastRadiusRatio + 'x ratio')})${blastNote}`
  ]);

  // License Compliance
  let licenseColor = pc.green;
  let licenseVerdict = 'Commercial Safe ✅';
  if (analysis.license.category === 'STRONG_COPYLEFT') {
    licenseColor = pc.red;
    licenseVerdict = 'Copyleft Risk (GPL/AGPL) ⚠️';
  } else if (analysis.license.category === 'WEAK_COPYLEFT') {
    licenseColor = pc.yellow;
    licenseVerdict = 'Weak Copyleft (LGPL/MPL) ℹ️';
  } else if (analysis.license.riskLevel === 'HIGH') {
    licenseColor = pc.red;
    licenseVerdict = 'High Risk / Ambiguous ⚠️';
  }

  table.push([
    pc.bold('License Compliance'),
    licenseColor(`${analysis.license.label} (${analysis.license.category}) — ${licenseVerdict}`)
  ]);

  // Downloads
  table.push([
    pc.bold('Downloads (Weekly)'),
    `${pc.bold(formatNumber(analysis.downloadsWeekly))} / week`
  ]);

  // Maintenance & Abandonware Health
  const formattedRelease = analysis.releaseDate
    ? analysis.releaseDate.toISOString().split('T')[0]
    : 'Unknown';

  let maintenanceNote = '';
  if (analysis.maintenance.isAbandoned) {
    maintenanceNote = pc.red(`\n⚠️ UNMAINTAINED: Last release was > 2 years ago!`);
  } else if (analysis.maintenance.isStale) {
    maintenanceNote = pc.yellow(`\n⚠️ STALE: No releases in over a year.`);
  }

  if (analysis.maintenance.busFactorRisk) {
    maintenanceNote += pc.yellow(`\n⚠️ Bus Factor: Maintained by a single person.`);
  }

  table.push([
    pc.bold('Maintenance & Health'),
    `${analysis.maintainersCount} maintainer(s) • Last release: ${formattedRelease}${maintenanceNote}`
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
