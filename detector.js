// ── Threat intelligence data ──────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq',
  '.xyz', '.top', '.click', '.link',
  '.online', '.site', '.info', '.biz'
];

const TRUSTED_DOMAINS = [
  'google.com', 'github.com', 'microsoft.com', 'apple.com',
  'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
  'youtube.com', 'wikipedia.org', 'stackoverflow.com',
  'reddit.com', 'anthropic.com'
];

const BRAND_KEYWORDS = [
  'paypal', 'amazon', 'apple', 'microsoft', 'google',
  'facebook', 'netflix', 'instagram', 'bank', 'secure',
  'verify', 'account', 'login', 'signin', 'update'
];

const PHISH_PATTERNS = [
  'verify', 'suspended', 'confirm', 'recover',
  'alert', 'security', 'urgent', 'locked', 'validate'
];

// ── URL utilities ─────────────────────────────────────────────────────────────

/**
 * Safely parse a raw URL string into a URL object.
 * Prepends https:// if no scheme is present.
 * @param {string} raw
 * @returns {URL|null}
 */
function parseURL(raw) {
  try {
    return new URL(raw.startsWith('http') ? raw : 'https://' + raw);
  } catch {
    return null;
  }
}

// ── Analysis engine ───────────────────────────────────────────────────────────

/**
 * Run all heuristic checks against a URL and return a structured report.
 * @param {string} raw  The raw URL string entered by the user.
 * @returns {{ error?: boolean, raw: string, url?: URL, host?: string,
 *             domain?: string, tld?: string, checks?: object[], riskScore?: number }}
 */
function buildReport(raw) {
  const url = parseURL(raw);
  if (!url) return { error: true, raw };

  const host      = url.hostname.toLowerCase();
  const fullPath  = url.pathname + url.search;
  const tld       = '.' + host.split('.').pop();
  const domainParts = host.split('.');
  const domain    = domainParts.slice(-2).join('.');

  const checks = [];
  let riskScore = 0;

  // 1 · HTTPS
  const isHTTPS = url.protocol === 'https:';
  checks.push({
    id: 'https',
    label: 'HTTPS Protocol',
    pass: isHTTPS ? 'pass' : 'fail',
    detail: isHTTPS
      ? 'Connection uses encrypted HTTPS'
      : 'Unencrypted HTTP — credentials may be exposed'
  });
  if (!isHTTPS) riskScore += 25;

  // 2 · Suspicious TLD
  const suspTLD = SUSPICIOUS_TLDS.includes(tld);
  checks.push({
    id: 'tld',
    label: 'Domain Extension (TLD)',
    pass: suspTLD ? 'fail' : 'pass',
    detail: suspTLD
      ? `"${tld}" is a free/high-abuse TLD frequently used in phishing`
      : `"${tld}" is a standard domain extension`
  });
  if (suspTLD) riskScore += 30;

  // 3 · Trusted domain whitelist
  const isTrusted = TRUSTED_DOMAINS.some(d => domain === d || host === d);
  checks.push({
    id: 'trusted',
    label: 'Known Trusted Domain',
    pass: isTrusted ? 'pass' : 'warn',
    detail: isTrusted
      ? `"${domain}" is a recognized, trusted domain`
      : `"${domain}" is not on the trusted domain list`
  });
  if (!isTrusted) riskScore += 10;

  // 4 · Subdomain depth
  const subCount    = domainParts.length - 2;
  const tooManySubs = subCount >= 3;
  checks.push({
    id: 'subdomains',
    label: 'Subdomain Depth',
    pass: tooManySubs ? 'warn' : 'pass',
    detail: tooManySubs
      ? `${subCount} subdomains detected — phishing sites often nest deeply`
      : `${subCount === 0 ? 'No' : subCount} subdomain${subCount !== 1 ? 's' : ''} — looks normal`
  });
  if (tooManySubs) riskScore += 15;

  // 5 · Brand impersonation
  const hasBrandKw   = BRAND_KEYWORDS.filter(k => host.includes(k) && !isTrusted);
  const isBrandSpoof = hasBrandKw.length > 0;
  checks.push({
    id: 'brand',
    label: 'Brand Impersonation',
    pass: isBrandSpoof ? 'fail' : 'pass',
    detail: isBrandSpoof
      ? `Domain contains brand keyword "${hasBrandKw[0]}" but is not the official site`
      : 'No suspicious brand keywords detected in domain'
  });
  if (isBrandSpoof) riskScore += 35;

  // 6 · Phishing path patterns
  const phishInPath  = PHISH_PATTERNS.filter(p => fullPath.toLowerCase().includes(p));
  const hasPhishPath = phishInPath.length > 0;
  checks.push({
    id: 'path',
    label: 'Path & Query Analysis',
    pass: hasPhishPath ? 'warn' : 'pass',
    detail: hasPhishPath
      ? `Path contains suspicious keywords: ${phishInPath.slice(0, 2).map(p => `"${p}"`).join(', ')}`
      : 'No suspicious terms found in URL path'
  });
  if (hasPhishPath) riskScore += 15;

  // 7 · URL length
  const urlLen  = raw.length;
  const tooLong = urlLen > 100;
  checks.push({
    id: 'length',
    label: 'URL Length',
    pass: tooLong ? 'warn' : 'pass',
    detail: `${urlLen} characters — ${tooLong
      ? 'unusually long URLs can obscure true destinations'
      : 'within a normal length range'}`
  });
  if (tooLong) riskScore += 10;

  // 8 · Numeric IP host
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  checks.push({
    id: 'ip',
    label: 'IP Address as Host',
    pass: isIP ? 'fail' : 'pass',
    detail: isIP
      ? 'Using raw IP instead of domain — a classic phishing indicator'
      : 'Using a proper domain name, not a raw IP'
  });
  if (isIP) riskScore += 40;

  // 9 · Homograph / lookalike chars
  const lookalikes    = /[0oO1lI]/.test(host.replace(/www\./, '').split('.')[0]);
  const hasLookalike  = lookalikes && !isTrusted;
  checks.push({
    id: 'homograph',
    label: 'Homograph / Lookalike Chars',
    pass: hasLookalike ? 'warn' : 'pass',
    detail: hasLookalike
      ? 'Domain may use visually similar characters (0 for o, 1 for l) to mimic real sites'
      : 'No obvious character substitution detected'
  });
  if (hasLookalike) riskScore += 10;

  return { url, raw, host, domain, tld, checks, riskScore: Math.min(100, riskScore) };
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/**
 * Render the analysis report into the #result element.
 * @param {{ error?: boolean, raw: string, url?: URL, host?: string,
 *           domain?: string, tld?: string, checks?: object[], riskScore?: number }} report
 */
function renderResult(report) {
  const el = document.getElementById('result');

  if (report.error) {
    el.innerHTML = `
      <div class="result-card">
        <div class="result-header verdict-warn">
          <div class="verdict-icon">⚠️</div>
          <div class="verdict-label">
            <h2>Invalid URL</h2>
            <p>Could not parse "${report.raw}". Please enter a valid URL.</p>
          </div>
        </div>
      </div>`;
    el.classList.add('visible');
    return;
  }

  const { url, domain, tld, checks, riskScore } = report;

  // Verdict
  let verdictClass, verdictLabel, verdictDesc, verdictEmoji;
  if (riskScore >= 50) {
    verdictClass = 'verdict-danger';
    verdictLabel = 'HIGH RISK — Likely Phishing';
    verdictDesc  = 'Multiple indicators suggest this URL is malicious. Do not visit or submit any credentials.';
    verdictEmoji = '🚨';
  } else if (riskScore >= 20) {
    verdictClass = 'verdict-warn';
    verdictLabel = 'SUSPICIOUS — Proceed with Caution';
    verdictDesc  = 'Some warning signs detected. Verify the source before clicking or entering any information.';
    verdictEmoji = '⚠️';
  } else {
    verdictClass = 'verdict-safe';
    verdictLabel = 'APPEARS SAFE';
    verdictDesc  = 'No major threat indicators detected. Always stay vigilant — no tool is 100% accurate.';
    verdictEmoji = '✅';
  }

  // URL breakdown tokens
  const scheme       = url.protocol.replace(':', '');
  const pathPart     = url.pathname !== '/' ? url.pathname : '';
  const paramPart    = url.search || '';
  const isSuspDomain = checks.find(c => c.id === 'brand')?.pass === 'fail';
  const isSuspTLD    = checks.find(c => c.id === 'tld')?.pass === 'fail';

  const urlHTML = `
    <span class="url-part scheme">${scheme}</span>
    <span class="url-sep">://</span>
    <span class="url-part domain ${isSuspDomain ? 'suspicious' : ''}">${domain.split('.')[0]}</span>
    <span class="url-sep">.</span>
    <span class="url-part tld ${isSuspTLD ? 'suspicious' : ''}">${tld.replace('.', '')}</span>
    ${pathPart  ? `<span class="url-sep">/</span><span class="url-part path">${pathPart.replace('/', '')}</span>` : ''}
    ${paramPart ? `<span class="url-part param">${paramPart.substring(0, 30)}${paramPart.length > 30 ? '…' : ''}</span>` : ''}
  `;

  const checksHTML = checks.map(c => `
    <div class="check-item check-${c.pass}">
      <div class="check-dot"></div>
      <div class="check-info">
        <h4>${c.label}</h4>
        <p>${c.detail}</p>
      </div>
    </div>
  `).join('');

  el.innerHTML = `
    <div class="result-card">
      <div class="result-header ${verdictClass}">
        <div class="verdict-icon">${verdictEmoji}</div>
        <div class="verdict-label">
          <h2>${verdictLabel}</h2>
          <p>${verdictDesc}</p>
        </div>
        <div class="risk-score">
          <div class="score">${riskScore}</div>
          <div class="label">RISK SCORE</div>
        </div>
      </div>
      <div class="checks-grid">${checksHTML}</div>
      <div class="url-breakdown">
        <div class="section-label">// URL breakdown</div>
        <div class="url-parts">${urlHTML}</div>
      </div>
    </div>`;

  el.classList.add('visible');
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── UI event handlers ─────────────────────────────────────────────────────────

/**
 * Fill the input with an example URL and run a scan immediately.
 * @param {string} url
 */
function fillExample(url) {
  document.getElementById('url-input').value = url;
  analyzeURL();
}

/** Read the input, show the loading state, then run analysis after a short delay. */
function analyzeURL() {
  const raw = document.getElementById('url-input').value.trim();
  if (!raw) return;

  document.getElementById('loading').classList.add('visible');
  document.getElementById('result').classList.remove('visible');
  document.getElementById('scan-btn').disabled = true;

  const delay = 900 + Math.random() * 600;
  setTimeout(() => {
    document.getElementById('loading').classList.remove('visible');
    document.getElementById('scan-btn').disabled = false;
    renderResult(buildReport(raw));
  }, delay);
}

// Enter key triggers scan
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') analyzeURL();
});
