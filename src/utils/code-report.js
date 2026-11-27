// Self-contained HTML report for an Opengrep code scan. No external
// resources: inline CSS only, no scripts, images or links other than
// in-page anchors. All SARIF text is escaped.

export const LEVEL_ORDER = ['error', 'warning', 'note', 'none'];

const LEVEL_TITLES = {
    error: 'Error',
    warning: 'Warning',
    note: 'Note',
    none: 'Unrated'
};

export function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Same palette and type as the summary page's default stylesheet.
const CSS = `
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f5f5f5; color: #222; }
header { background: #2c3e50; color: #fff; padding: 20px 32px; }
header h1 { margin: 0 0 8px; font-size: 22px; }
header p { margin: 2px 0; font-size: 14px; color: #dfe6ec; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
section { background: #fff; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; padding: 16px 20px; }
h2 { margin-top: 0; font-size: 18px; }
.finding { border-top: 1px solid #e3e3e3; padding: 12px 0; }
.finding:first-of-type { border-top: none; }
.rule { font-family: ui-monospace, Menlo, monospace; font-size: 13px; word-break: break-all; }
.location { font-family: ui-monospace, Menlo, monospace; color: #555; }
.cwe { color: #8e44ad; font-size: 13px; }
.flow { margin: 6px 0 0 18px; font-size: 13px; }
.level-error h2 { color: #c0392b; }
.level-warning h2 { color: #d68910; }
.level-note h2 { color: #2471a3; }
.empty { font-size: 16px; }
`;

export function resultLevel(result, rule) {
    return result.level || rule?.defaultConfiguration?.level || 'none';
}

function formatLocation(physicalLocation) {
    const file = physicalLocation?.artifactLocation?.uri || 'unknown location';
    const line = physicalLocation?.region?.startLine;
    return line ? `${file}:${line}` : file;
}

function ruleFor(result, rules) {
    if (Number.isInteger(result.ruleIndex) && rules[result.ruleIndex]) return rules[result.ruleIndex];
    return rules.find((rule) => rule.id === result.ruleId) || null;
}

export function cweTags(rule) {
    const tags = rule?.properties?.tags || [];
    const fromTags = tags.filter((tag) => /^CWE-\d+/i.test(tag));
    const fromProperty = Array.isArray(rule?.properties?.cwe) ? rule.properties.cwe : [];
    return [...fromTags, ...fromProperty.filter((cwe) => !fromTags.some((tag) => tag.startsWith(cwe)))];
}

function flowSteps(result) {
    const steps = [];
    for (const codeFlow of result.codeFlows || []) {
        for (const threadFlow of codeFlow.threadFlows || []) {
            for (const step of threadFlow.locations || []) {
                const location = step.location || {};
                steps.push({
                    where: formatLocation(location.physicalLocation),
                    text: location.message?.text || ''
                });
            }
        }
    }
    return steps;
}

// counted: results at or above the threshold (already filtered by the caller).
export function renderOpengrepReport({ sarif, counted, engineVersion, severityThreshold, generatedAt }) {
    const run = sarif?.runs?.[0] || {};
    const rules = run.tool?.driver?.rules || [];
    const groups = new Map(LEVEL_ORDER.map((level) => [level, []]));
    for (const result of counted) {
        const rule = ruleFor(result, rules);
        const level = resultLevel(result, rule);
        (groups.get(level) || groups.get('none')).push({ result, rule });
    }

    const parts = [];
    parts.push('<!doctype html>');
    parts.push('<html lang="en"><head><meta charset="utf-8">');
    parts.push('<meta name="viewport" content="width=device-width, initial-scale=1">');
    parts.push('<title>Code audit (Opengrep)</title>');
    parts.push(`<style>${CSS}</style></head><body>`);
    parts.push('<header>');
    parts.push('<h1>Code audit</h1>');
    parts.push(`<p>Engine: Opengrep ${escapeHtml(engineVersion || '')}</p>`);
    parts.push(`<p>Severity threshold: ${escapeHtml(severityThreshold)}</p>`);
    parts.push(`<p>Findings at or above the threshold: ${counted.length} of ${(run.results || []).length}</p>`);
    parts.push(`<p>Generated: ${escapeHtml(generatedAt)}</p>`);
    parts.push('</header><main>');

    if (counted.length === 0) {
        parts.push(`<section><p class="empty">No findings met the severity threshold "${escapeHtml(severityThreshold)}".</p></section>`);
    }

    for (const level of LEVEL_ORDER) {
        const items = groups.get(level);
        if (!items.length) continue;
        parts.push(`<section class="level-${level}" id="level-${level}">`);
        parts.push(`<h2>${LEVEL_TITLES[level]} (${items.length})</h2>`);
        for (const { result, rule } of items) {
            const location = result.locations?.[0]?.physicalLocation;
            parts.push('<div class="finding">');
            parts.push(`<div class="rule">${escapeHtml(result.ruleId || rule?.id || 'unknown rule')}</div>`);
            parts.push(`<div class="location">${escapeHtml(formatLocation(location))}</div>`);
            parts.push(`<p>${escapeHtml(result.message?.text || rule?.shortDescription?.text || '')}</p>`);
            const cwes = cweTags(rule);
            if (cwes.length) parts.push(`<div class="cwe">${cwes.map(escapeHtml).join('; ')}</div>`);
            const steps = flowSteps(result);
            if (steps.length) {
                parts.push('<ol class="flow">');
                for (const step of steps) {
                    parts.push(`<li><span class="location">${escapeHtml(step.where)}</span> ${escapeHtml(step.text)}</li>`);
                }
                parts.push('</ol>');
            }
            parts.push('</div>');
        }
        parts.push('</section>');
    }

    parts.push('</main></body></html>');
    return `${parts.join('\n')}\n`;
}
