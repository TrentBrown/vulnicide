// Snyk upgrade advice, shared by `deps explain` packets and `deps gate`
// findings so both describe upgrades the same way.

// Index Snyk's `remediation.upgrade` ("pkg@ver" -> {upgradeTo, upgrades,
// vulns}) by vulnerability ID.
export function indexUpgradeRemediation(upgradeRemediation) {
    const byVuln = new Map();
    for (const [dependency, advice] of Object.entries(upgradeRemediation)) {
        for (const vulnId of advice.vulns || []) {
            if (!byVuln.has(vulnId)) {
                byVuln.set(vulnId, []);
            }
            byVuln.get(vulnId).push({
                dependency,
                upgradeTo: advice.upgradeTo,
                upgrades: advice.upgrades || []
            });
        }
    }
    return byVuln;
}

// Advice entries for the given vulnerability IDs, deduplicated by
// dependency and target version.
export function collectUpgradeAdvice(vulnerabilityIds, upgradeRemediationByVuln) {
    const seen = new Set();
    const advice = [];
    for (const id of vulnerabilityIds) {
        for (const entry of upgradeRemediationByVuln.get(id) || []) {
            const key = `${entry.dependency}->${entry.upgradeTo}`;
            if (!seen.has(key)) {
                seen.add(key);
                advice.push(entry);
            }
        }
    }
    return advice;
}
