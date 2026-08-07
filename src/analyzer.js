/**
 * @file analyzer.js
 * Security risk scoring, license parsing, and bundle footprint engine.
 */

const PERMISSIVE = new Set(['MIT', 'APACHE-2.0', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'ISC', 'UNLICENSE', 'CC0-1.0', 'WTFPL']);
const COPYLEFT = new Set(['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0']);

export function formatBytes(bytes) {
  if (!bytes || isNaN(bytes) || bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function analyzeLicense(licenseRaw) {
  let name = typeof licenseRaw === 'string' ? licenseRaw.trim().toUpperCase() : (licenseRaw?.type || licenseRaw?.name || 'UNKNOWN').trim().toUpperCase();
  const clean = name.replace(/[()]/g, '');
  if (clean === 'UNKNOWN' || clean === 'SEE LICENSE IN LICENSE') return { category: 'UNKNOWN', label: name || 'UNKNOWN', riskLevel: 'HIGH' };
  if (PERMISSIVE.has(clean) || clean.includes('MIT') || clean.includes('APACHE')) return { category: 'PERMISSIVE', label: name, riskLevel: 'LOW' };
  if (COPYLEFT.has(clean) || clean.includes('GPL')) return { category: 'COPYLEFT', label: name, riskLevel: 'MODERATE' };
  return { category: 'CUSTOM/OTHER', label: name, riskLevel: 'MODERATE' };
}

export function auditLifecycleScripts(scripts = {}) {
  const hooks = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall']
    .filter((name) => scripts[name])
    .map((name) => ({ name, command: scripts[name] }));
  return { hasDangerousHooks: hooks.length > 0, hooks };
}

export function analyzeFootprint(details) {
  const bundle = details.bundleMetrics, dist = details.dist || {};
  const minifiedBytes = bundle?.size || dist.unpackedSize || 0;
  const gzippedBytes = bundle?.gzip || (dist.unpackedSize ? Math.round(dist.unpackedSize * 0.3) : 0);
  return {
    minifiedBytes, minifiedFormatted: formatBytes(minifiedBytes),
    gzippedBytes, gzippedFormatted: formatBytes(gzippedBytes),
    isTreeShakeable: Boolean(bundle?.hasJSModule || bundle?.hasJSNext || bundle?.sideEffects === false),
    directDependenciesCount: Object.keys(details.dependencies || {}).length,
    totalDependenciesCount: bundle?.dependencyCount ?? Object.keys(details.dependencies || {}).length
  };
}

export function calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis) {
  let score = 0;
  const riskFactors = [];

  if (scriptAudit.hasDangerousHooks) { score += 40; riskFactors.push(`Contains lifecycle script hooks (${scriptAudit.hooks.map(h => h.name).join(', ')})`); }
  if (rawDetails.deprecated) { score += 35; riskFactors.push(`Package is DEPRECATED: "${rawDetails.deprecated}"`); }
  if (licenseAnalysis.riskLevel === 'HIGH') { score += 20; riskFactors.push('Unspecified license'); }
  if (!rawDetails.maintainers?.length) { score += 15; riskFactors.push('No maintainers specified'); }
  if (rawDetails.releaseDate) {
    const years = (Date.now() - rawDetails.releaseDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
    if (years > 3) { score += 15; riskFactors.push(`Last release was over ${Math.floor(years)} years ago`); }
  }
  if (rawDetails.downloadsWeekly > 100000) score = Math.max(0, score - 10);

  const normalizedScore = Math.min(100, Math.max(0, score));
  const safetyScore = 100 - normalizedScore;

  let level = 'LOW';
  if (normalizedScore >= 75) level = 'CRITICAL';
  else if (normalizedScore >= 50) level = 'HIGH';
  else if (normalizedScore >= 25) level = 'MODERATE';

  return { score: normalizedScore, safetyScore, level, riskFactors };
}

export function analyzePackage(rawDetails) {
  const licenseAnalysis = analyzeLicense(rawDetails.license);
  const scriptAudit = auditLifecycleScripts(rawDetails.scripts);
  return {
    name: rawDetails.name, version: rawDetails.version, description: rawDetails.description,
    author: rawDetails.author, maintainersCount: rawDetails.maintainers?.length || 0,
    downloadsWeekly: rawDetails.downloadsWeekly, releaseDate: rawDetails.releaseDate,
    deprecated: rawDetails.deprecated, license: licenseAnalysis, scriptAudit,
    footprint: analyzeFootprint(rawDetails), security: calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis)
  };
}
