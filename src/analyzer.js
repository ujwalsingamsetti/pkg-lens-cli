/**
 * @file analyzer.js
 * Security risk scoring, license parsing, typosquatting detection, and bundle footprint engine.
 */

const PERMISSIVE = new Set(['MIT', 'APACHE-2.0', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'ISC', 'UNLICENSE', 'CC0-1.0', 'WTFPL']);
const COPYLEFT = new Set(['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0']);

/**
 * Popular npm package names targets for typosquatting checks
 */
const POPULAR_TARGETS = [
  'express', 'react', 'react-dom', 'vue', 'angular', 'lodash', 'axios', 'next', 'nuxt',
  'typescript', 'webpack', 'jest', 'vite', 'fastify', 'commander', 'moment', 'dayjs',
  'eslint', 'prettier', 'tailwindcss', 'cypress', 'vitest', 'rxjs', 'mongoose', 'prisma'
];

/**
 * Compute Levenshtein distance between two strings
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

/**
 * Detect typosquatting supply chain risk
 */
export function detectTyposquatting(name) {
  const lower = name.toLowerCase().trim();
  if (POPULAR_TARGETS.includes(lower)) return { isTyposquat: false, similarTo: null };

  for (const target of POPULAR_TARGETS) {
    const dist = levenshtein(lower, target);
    if (dist === 1 || (dist === 2 && lower.length > 5)) {
      return { isTyposquat: true, similarTo: target };
    }
  }

  return { isTyposquat: false, similarTo: null };
}

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

export function calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis, typosquat, vulns = []) {
  let score = 0;
  const riskFactors = [];

  // OSV Vulnerabilities (+50 for vulnerabilities)
  if (vulns.length > 0) {
    score += Math.min(60, vulns.length * 30);
    riskFactors.push(`Contains ${vulns.length} reported CVE security vulnerability advisory(ies)`);
  }

  // Typosquatting alert (+45 risk)
  if (typosquat.isTyposquat) {
    score += 45;
    riskFactors.push(`POSSIBLE TYPOSQUATTING: Name is suspiciously similar to popular package "${typosquat.similarTo}"`);
  }

  if (scriptAudit.hasDangerousHooks) { score += 40; riskFactors.push(`Contains lifecycle script hooks (${scriptAudit.hooks.map(h => h.name).join(', ')})`); }
  if (rawDetails.deprecated) { score += 35; riskFactors.push(`Package is DEPRECATED: "${rawDetails.deprecated}"`); }
  if (licenseAnalysis.riskLevel === 'HIGH') { score += 20; riskFactors.push('Unspecified license'); }
  if (!rawDetails.maintainers?.length) { score += 15; riskFactors.push('No maintainers specified'); }
  if (rawDetails.releaseDate) {
    const years = (Date.now() - rawDetails.releaseDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
    if (years > 3) { score += 15; riskFactors.push(`Last release was over ${Math.floor(years)} years ago`); }
  }
  if (rawDetails.downloadsWeekly > 100000 && !typosquat.isTyposquat) score = Math.max(0, score - 10);

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
  const typosquat = detectTyposquatting(rawDetails.name);
  const vulns = rawDetails.vulnerabilities || [];
  const security = calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis, typosquat, vulns);

  return {
    name: rawDetails.name, version: rawDetails.version, description: rawDetails.description,
    author: rawDetails.author, maintainersCount: rawDetails.maintainers?.length || 0,
    downloadsWeekly: rawDetails.downloadsWeekly, releaseDate: rawDetails.releaseDate,
    deprecated: rawDetails.deprecated, license: licenseAnalysis, scriptAudit, typosquat,
    vulnerabilities: vulns, footprint: analyzeFootprint(rawDetails), security
  };
}
