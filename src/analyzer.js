/**
 * @file analyzer.js
 * Security risk scoring, license compliance, typosquatting detection,
 * maintenance health, dependency blast radius, and bundle footprint engine.
 */

import { getAlternativeRecommendation } from './alternatives.js';

const PERMISSIVE_LICENSES = new Set([
  'MIT', 'APACHE-2.0', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'ISC', 'UNLICENSE',
  'CC0-1.0', 'WTFPL', '0BSD', 'ZLIB', 'PYTHON-2.0'
]);

const WEAK_COPYLEFT_LICENSES = new Set([
  'LGPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-1.1', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0'
]);

const STRONG_COPYLEFT_LICENSES = new Set([
  'GPL-2.0', 'GPL-3.0', 'AGPL-1.0', 'AGPL-3.0', 'SSPL-1.0', 'EUPL-1.1', 'EUPL-1.2'
]);

/**
 * Popular npm package names targeted for typosquatting checks
 */
const POPULAR_TARGETS = [
  'express', 'react', 'react-dom', 'vue', 'angular', 'lodash', 'axios', 'next', 'nuxt',
  'typescript', 'webpack', 'jest', 'vite', 'fastify', 'commander', 'moment', 'dayjs',
  'eslint', 'prettier', 'tailwindcss', 'cypress', 'vitest', 'rxjs', 'mongoose', 'prisma',
  'chalk', 'ora', 'dotenv', 'nodemon', 'cors', 'zod', 'yargs', 'glob'
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

/**
 * Analyze package license with commercial compliance classification
 */
export function analyzeLicense(licenseRaw) {
  let name = typeof licenseRaw === 'string'
    ? licenseRaw.trim().toUpperCase()
    : (licenseRaw?.type || licenseRaw?.name || 'UNKNOWN').trim().toUpperCase();

  const clean = name.replace(/[()]/g, '');

  if (clean === 'UNKNOWN' || clean === 'SEE LICENSE IN LICENSE' || clean === 'UNLICENSED' || !clean) {
    return {
      category: 'UNKNOWN',
      label: name || 'UNKNOWN',
      riskLevel: 'HIGH',
      commercialSafe: false,
      description: 'Unspecified or ambiguous license. High legal uncertainty for proprietary use.'
    };
  }

  if (PERMISSIVE_LICENSES.has(clean) || clean.includes('MIT') || clean.includes('APACHE') || clean.includes('BSD')) {
    return {
      category: 'PERMISSIVE',
      label: name,
      riskLevel: 'LOW',
      commercialSafe: true,
      description: 'Permissive open-source license. Safe for commercial and proprietary applications.'
    };
  }

  if (WEAK_COPYLEFT_LICENSES.has(clean) || clean.includes('LGPL') || clean.includes('MPL')) {
    return {
      category: 'WEAK_COPYLEFT',
      label: name,
      riskLevel: 'MODERATE',
      commercialSafe: true,
      description: 'Weak copyleft. Modifying library files requires disclosure, but proprietary linking is permitted.'
    };
  }

  if (STRONG_COPYLEFT_LICENSES.has(clean) || clean.includes('AGPL') || clean.includes('GPL-3.0') || clean.includes('GPL-2.0') || clean.includes('GPL')) {
    return {
      category: 'STRONG_COPYLEFT',
      label: name,
      riskLevel: 'HIGH',
      commercialSafe: false,
      description: 'Strong copyleft (GPL/AGPL). May compel proprietary products to open-source all code.'
    };
  }

  return {
    category: 'CUSTOM/OTHER',
    label: name,
    riskLevel: 'MODERATE',
    commercialSafe: true,
    description: 'Custom or non-standard license. Review terms manually.'
  };
}

export function auditLifecycleScripts(scripts = {}) {
  const hooks = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall']
    .filter((name) => scripts[name])
    .map((name) => ({ name, command: scripts[name] }));
  return { hasDangerousHooks: hooks.length > 0, hooks };
}

/**
 * Analyze maintenance activity, bus factor, and abandonware risk
 */
export function analyzeMaintenance(details) {
  const maintainers = details.maintainers || [];
  const maintainerCount = Array.isArray(maintainers) ? maintainers.length : (maintainers ? 1 : 0);
  const isDeprecated = Boolean(details.deprecated);

  let monthsSinceRelease = 0;
  let isAbandoned = false;
  let isStale = false;

  if (details.releaseDate) {
    const msSince = Date.now() - details.releaseDate.getTime();
    monthsSinceRelease = Math.max(0, Math.round(msSince / (1000 * 60 * 60 * 24 * 30.4375)));
    if (monthsSinceRelease >= 24) {
      isAbandoned = true;
    } else if (monthsSinceRelease >= 12) {
      isStale = true;
    }
  }

  const busFactorRisk = maintainerCount === 1;

  return {
    maintainerCount,
    busFactorRisk,
    isDeprecated,
    deprecationMessage: details.deprecated || null,
    monthsSinceRelease,
    isAbandoned,
    isStale
  };
}

/**
 * Analyze bundle footprint, direct dependencies, and transitive blast radius
 */
export function analyzeFootprint(details) {
  const bundle = details.bundleMetrics, dist = details.dist || {};
  const minifiedBytes = bundle?.size || dist.unpackedSize || 0;
  const gzippedBytes = bundle?.gzip || (dist.unpackedSize ? Math.round(dist.unpackedSize * 0.3) : 0);

  const directDependenciesCount = Object.keys(details.dependencies || {}).length;
  const totalDependenciesCount = bundle?.dependencyCount ?? directDependenciesCount;
  const transitiveDependenciesCount = Math.max(0, totalDependenciesCount - directDependenciesCount);
  const blastRadiusRatio = directDependenciesCount > 0
    ? (totalDependenciesCount / directDependenciesCount).toFixed(1)
    : String(totalDependenciesCount);

  const isHighBlastRadius = totalDependenciesCount >= 25 && directDependenciesCount <= 3;

  return {
    minifiedBytes,
    minifiedFormatted: formatBytes(minifiedBytes),
    gzippedBytes,
    gzippedFormatted: formatBytes(gzippedBytes),
    isTreeShakeable: Boolean(bundle?.hasJSModule || bundle?.hasJSNext || bundle?.sideEffects === false),
    directDependenciesCount,
    totalDependenciesCount,
    transitiveDependenciesCount,
    blastRadiusRatio,
    isHighBlastRadius
  };
}

export function calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis, typosquat, vulns = [], maintenance = null) {
  let score = 0;
  const riskFactors = [];

  // OSV Vulnerabilities (+30 per CVE, capped at 60)
  if (vulns.length > 0) {
    score += Math.min(60, vulns.length * 30);
    riskFactors.push(`Contains ${vulns.length} reported CVE security vulnerability advisory(ies)`);
  }

  // Typosquatting alert (+45 risk)
  if (typosquat.isTyposquat) {
    score += 45;
    riskFactors.push(`POSSIBLE TYPOSQUATTING: Name is suspiciously similar to popular package "${typosquat.similarTo}"`);
  }

  // Lifecycle scripts (+40 risk)
  if (scriptAudit.hasDangerousHooks) {
    score += 40;
    riskFactors.push(`Contains lifecycle script hooks (${scriptAudit.hooks.map(h => h.name).join(', ')})`);
  }

  // Deprecation (+35 risk)
  if (rawDetails.deprecated) {
    score += 35;
    riskFactors.push(`Package is DEPRECATED: "${rawDetails.deprecated}"`);
  }

  // Strong Copyleft License (+25 risk for commercial risk)
  if (licenseAnalysis.category === 'STRONG_COPYLEFT') {
    score += 25;
    riskFactors.push(`Strong Copyleft license (${licenseAnalysis.label}) — high commercial legal risk`);
  } else if (licenseAnalysis.riskLevel === 'HIGH') {
    score += 20;
    riskFactors.push('Unspecified or ambiguous license');
  }

  // Maintenance & Abandonware
  if (maintenance) {
    if (maintenance.isAbandoned) {
      score += 20;
      riskFactors.push(`ABANDONWARE: No release in ${maintenance.monthsSinceRelease} months (>= 2 years)`);
    } else if (maintenance.isStale) {
      score += 10;
      riskFactors.push(`STALE: Last release was ${maintenance.monthsSinceRelease} months ago (> 1 year)`);
    }

    if (maintenance.maintainerCount === 0) {
      score += 15;
      riskFactors.push('No maintainers specified on npm registry');
    }
  }

  // Download popularity discount (only if legitimate package)
  if (rawDetails.downloadsWeekly > 100000 && !typosquat.isTyposquat) {
    score = Math.max(0, score - 10);
  }

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
  const maintenance = analyzeMaintenance(rawDetails);
  const security = calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis, typosquat, vulns, maintenance);
  const footprint = analyzeFootprint(rawDetails);
  const alternative = getAlternativeRecommendation(rawDetails.name);

  return {
    name: rawDetails.name,
    version: rawDetails.version,
    description: rawDetails.description,
    author: rawDetails.author,
    maintainersCount: maintenance.maintainerCount,
    downloadsWeekly: rawDetails.downloadsWeekly,
    releaseDate: rawDetails.releaseDate,
    deprecated: rawDetails.deprecated,
    license: licenseAnalysis,
    scriptAudit,
    typosquat,
    maintenance,
    vulnerabilities: vulns,
    footprint,
    alternative,
    security
  };
}
