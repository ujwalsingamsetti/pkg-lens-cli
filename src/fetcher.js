/**
 * @file fetcher.js
 * NPM Registry & Bundlephobia HTTP Data Fetcher.
 */

import https from 'node:https';

/**
 * Fetch JSON payload from HTTPS URL with timeout.
 */
async function fetchJson(url, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'pkg-lens-cli/1.0.2' } }, (res) => {
      if (res.statusCode === 404) return reject(new Error(`Package not found (404)`));
      if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error(`Timeout (${timeoutMs}ms)`)); });
  });
}

/**
 * Parse specifier into package name and version tag.
 */
export function parsePackageSpec(specifier) {
  const trimmed = (specifier || '').trim();
  if (!trimmed) throw new Error('Invalid specifier');

  if (trimmed.startsWith('@')) {
    const slashIdx = trimmed.indexOf('/');
    if (slashIdx === -1) return { name: trimmed, versionSpec: 'latest' };
    const atIdx = trimmed.indexOf('@', slashIdx);
    return atIdx === -1 ? { name: trimmed, versionSpec: 'latest' } : { name: trimmed.slice(0, atIdx), versionSpec: trimmed.slice(atIdx + 1) || 'latest' };
  }

  const atIdx = trimmed.indexOf('@');
  return atIdx === -1 ? { name: trimmed, versionSpec: 'latest' } : { name: trimmed.slice(0, atIdx), versionSpec: trimmed.slice(atIdx + 1) || 'latest' };
}

/**
 * Fetch consolidated package metadata.
 */
export async function fetchPackageDetails(specifier) {
  const { name, versionSpec } = parsePackageSpec(specifier);
  const meta = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`, 8000);

  const distTags = meta['dist-tags'] || {};
  let targetVersion = versionSpec === 'latest' || !versionSpec ? (distTags.latest || Object.keys(meta.versions || {}).pop()) : (distTags[versionSpec] || versionSpec);
  const versionData = meta.versions?.[targetVersion];
  if (!versionData) throw new Error(`Version '${versionSpec}' for package '${name}' not found.`);

  const [downloadsWeekly, bundleMetrics] = await Promise.all([
    fetchJson(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`, 4000).then((d) => d.downloads || 0).catch(() => 0),
    fetchJson(`https://bundlephobia.com/api/size?package=${encodeURIComponent(name)}@${targetVersion}`, 6000).catch(() => null)
  ]);

  const timeMap = meta.time || {};
  return {
    name,
    version: targetVersion,
    description: versionData.description || meta.description || 'No description provided.',
    license: versionData.license || meta.license || 'UNKNOWN',
    author: versionData.author?.name || versionData.author || meta.author?.name || meta.author || 'Unknown',
    maintainers: meta.maintainers || versionData.maintainers || [],
    dependencies: versionData.dependencies || {},
    scripts: versionData.scripts || {},
    deprecated: versionData.deprecated || false,
    dist: versionData.dist || {},
    downloadsWeekly,
    bundleMetrics,
    releaseDate: timeMap[targetVersion] ? new Date(timeMap[targetVersion]) : null
  };
}
