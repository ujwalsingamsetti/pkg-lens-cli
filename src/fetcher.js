/**
 * @file fetcher.js
 * NPM Registry, Bundlephobia, and Google OSV.dev HTTP Data Fetcher.
 */

import https from 'node:https';

/**
 * Fetch JSON payload from HTTPS URL with timeout (GET or POST).
 */
async function fetchJson(url, options = {}, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const isPost = options.method === 'POST';
    const bodyStr = isPost && options.body ? JSON.stringify(options.body) : null;

    const reqOptions = {
      method: isPost ? 'POST' : 'GET',
      headers: {
        'User-Agent': 'pkg-lens-cli/1.1.0',
        ...(isPost ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) } : {})
      }
    };

    const req = https.request(url, reqOptions, (res) => {
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
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/**
 * Query Google's OSV.dev Open Source Vulnerability Database for a package version.
 */
export async function fetchOsvVulnerabilities(name, version) {
  try {
    const payload = { package: { name, ecosystem: 'npm' }, version };
    const res = await fetchJson('https://api.osv.dev/v1/query', { method: 'POST', body: payload }, 6000);
    const vulns = res.vulns || [];
    return vulns.map((v) => ({
      id: v.id,
      summary: v.summary || v.details?.slice(0, 100) || 'Security advisory reported',
      aliases: v.aliases || [],
      severity: v.database_specific?.severity || (v.severity?.[0]?.type ? 'HIGH' : 'MODERATE')
    }));
  } catch (err) {
    return [];
  }
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
 * Fetch consolidated package metadata including OSV vulnerabilities.
 */
export async function fetchPackageDetails(specifier) {
  const { name, versionSpec } = parsePackageSpec(specifier);
  const meta = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`, {}, 8000);

  const distTags = meta['dist-tags'] || {};
  let targetVersion = versionSpec === 'latest' || !versionSpec ? (distTags.latest || Object.keys(meta.versions || {}).pop()) : (distTags[versionSpec] || versionSpec);
  const versionData = meta.versions?.[targetVersion];
  if (!versionData) throw new Error(`Version '${versionSpec}' for package '${name}' not found.`);

  const [downloadsWeekly, bundleMetrics, vulnerabilities] = await Promise.all([
    fetchJson(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`, {}, 4000).then((d) => d.downloads || 0).catch(() => 0),
    fetchJson(`https://bundlephobia.com/api/size?package=${encodeURIComponent(name)}@${targetVersion}`, {}, 6000).catch(() => null),
    fetchOsvVulnerabilities(name, targetVersion)
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
    vulnerabilities,
    releaseDate: timeMap[targetVersion] ? new Date(timeMap[targetVersion]) : null
  };
}
