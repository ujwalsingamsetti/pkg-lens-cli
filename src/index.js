/**
 * @file index.js
 * Main library entry point exporting programmatic API functions for pkg-lens.
 */

import { fetchPackageDetails } from './fetcher.js';
import { analyzePackage } from './analyzer.js';
import { formatPackageReport } from './formatter.js';
import { comparePackages } from './comparator.js';
import { safeInstallPackage } from './installer.js';
import { auditProject } from './auditor.js';
import { getAlternativeRecommendation } from './alternatives.js';

/**
 * Inspect an npm package programmatically.
 * @param {string} specifier - E.g. 'express' or 'express@4.18.2'
 * @param {object} [options] - Options
 * @param {boolean} [options.json=false] - Return raw JSON analysis object instead of formatted report
 * @returns {Promise<object|string>} Analysis object or formatted report string
 */
export async function inspectPackage(specifier, options = {}) {
  const rawDetails = await fetchPackageDetails(specifier);
  const analysis = analyzePackage(rawDetails);

  if (options.json) {
    return analysis;
  }

  return formatPackageReport(analysis);
}

export {
  fetchPackageDetails,
  analyzePackage,
  formatPackageReport,
  comparePackages,
  safeInstallPackage,
  auditProject,
  getAlternativeRecommendation
};
