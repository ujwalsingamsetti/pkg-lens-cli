import test from 'node:test';
import assert from 'node:assert/strict';
import { auditProject } from '../src/auditor.js';

test('auditProject parses and evaluates current directory package.json structure', async () => {
  const result = await auditProject('.');
  assert.equal(result.projectName, 'pkg-lens-cli');
  assert.equal(result.totalDependencies, 3);
  assert.ok(typeof result.overallScore === 'number');
  assert.ok(typeof result.reportTable === 'string');
  assert.ok(Array.isArray(result.analyzed));
  assert.equal(result.analyzed.length, 3);
});

test('auditProject throws clean error if directory has no package.json', async () => {
  await assert.rejects(
    async () => {
      await auditProject('./test');
    },
    /No package\.json found/
  );
});
