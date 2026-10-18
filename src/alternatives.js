/**
 * @file alternatives.js
 * Curated knowledge base of modern, lightweight, or native alternatives
 * for heavy, legacy, or deprecated npm packages.
 */

export const ALTERNATIVES = {
  moment: {
    alternatives: ['dayjs', 'date-fns'],
    reason: 'moment is legacy and large (~70 kB gzip). dayjs is ~2 kB with an almost identical API.',
    savings: '~68 kB (97% smaller)'
  },
  lodash: {
    alternatives: ['radash', 'native ES6+ (Array & Object methods)'],
    reason: 'lodash is ~24 kB gzip. Consider radash (~2 kB) or native JavaScript methods.',
    savings: '~22 kB (90% smaller)'
  },
  underscore: {
    alternatives: ['radash', 'native ES6+'],
    reason: 'Legacy utility library. Modern JavaScript includes native map, filter, reduce, find, etc.',
    savings: '~15 kB'
  },
  request: {
    alternatives: ['native fetch', 'undici', 'axios'],
    reason: 'request was fully deprecated in 2020. Use native global fetch (Node 18+) or undici.',
    savings: 'Deprecation fix'
  },
  'request-promise': {
    alternatives: ['native fetch', 'undici', 'axios'],
    reason: 'request-promise is deprecated along with request. Use native fetch.',
    savings: 'Deprecation fix'
  },
  chalk: {
    alternatives: ['picocolors', 'kleur', 'yoctocolors'],
    reason: 'picocolors is ~3 kB and 14x smaller with zero dependencies.',
    savings: '~30 kB'
  },
  uuid: {
    alternatives: ['crypto.randomUUID()'],
    reason: 'Node.js 16.7+ has native crypto.randomUUID() with zero external dependencies.',
    savings: '0 kB external dependency'
  },
  rimraf: {
    alternatives: ['fs.rm(path, { recursive: true, force: true })'],
    reason: 'Node.js 14.14+ provides native recursive directory deletion.',
    savings: '0 kB external dependency'
  },
  mkdirp: {
    alternatives: ['fs.mkdir(path, { recursive: true })'],
    reason: 'Node.js 10.12+ supports native recursive directory creation.',
    savings: '0 kB external dependency'
  },
  querystring: {
    alternatives: ['URLSearchParams'],
    reason: 'Node.js native URLSearchParams standard is modern and built-in.',
    savings: 'Built-in standard'
  },
  'node-fetch': {
    alternatives: ['native globalThis.fetch'],
    reason: 'Node 18+ provides global fetch built-in without needing node-fetch.',
    savings: 'Built-in standard'
  },
  isarray: {
    alternatives: ['Array.isArray()'],
    reason: 'Native JavaScript Array.isArray() has been standard since ES5.',
    savings: 'Micro-dependency elimination'
  },
  'is-odd': {
    alternatives: ['n % 2 !== 0'],
    reason: 'Trivial 1-line native bitwise or modulo check.',
    savings: 'Micro-dependency elimination'
  },
  'is-even': {
    alternatives: ['n % 2 === 0'],
    reason: 'Trivial 1-line native modulo check.',
    savings: 'Micro-dependency elimination'
  }
};

/**
 * Find recommended lightweight or modern alternatives for a package name.
 * @param {string} packageName - NPM package name
 * @returns {object|null} Alternative suggestion or null
 */
export function getAlternativeRecommendation(packageName) {
  if (!packageName) return null;
  const key = packageName.toLowerCase().trim();
  return ALTERNATIVES[key] || null;
}
