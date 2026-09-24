/* ==========================================================================
   THREATLENS — client-side demo rule engine
   DEMO RULE ENGINE — replace with Python backend later
   ========================================================================== */

(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* Constants & reference data                                          */
  /* ------------------------------------------------------------------ */

  const STAGE_IDS = [
    "parsed", "domain", "auth", "url", "impersonation",
    "language", "exposure", "campaign", "priority"
  ];

  const BRANDS = {
    paypal:     ["paypal.com"],
    microsoft:  ["microsoft.com", "outlook.com", "office.com", "office365.com", "live.com"],
    apple:      ["apple.com", "icloud.com"],
    amazon:     ["amazon.com"],
    google:     ["google.com", "gmail.com"],
    netflix:    ["netflix.com"],
    dhl:        ["dhl.com"],
    fedex:      ["fedex.com"],
    docusign:   ["docusign.com", "docusign.net"],
    linkedin:   ["linkedin.com"],
    chase:      ["chase.com"],
    bankofamerica: ["bankofamerica.com"],
    dropbox:    ["dropbox.com"],
    adobe:      ["adobe.com"]
  };

  const SUSPICIOUS_TLDS = ["xyz", "top", "club", "tk", "ml", "ga", "cf", "gq", "zip", "info", "click", "work", "loan", "men"];

  const URGENCY_WORDS = [
    "urgent", "immediately", "act now", "act fast", "right away", "within 24 hours",
    "within 12 hours", "expires today", "final notice", "last warning", "asap",
    "time-sensitive", "time sensitive", "before it's too late"
  ];

  const CREDENTIAL_WORDS = [
    "verify your account", "confirm your password", "login to verify", "update your password",
    "confirm your identity", "re-enter your password", "sign in to confirm", "verify your identity",
    "enter your credentials", "your password", "login credentials"
  ];

  const PAYMENT_WORDS = [
    "wire transfer", "gift card", "invoice attached", "outstanding invoice", "bank details",
    "payment is overdue", "processing fee", "update your billing", "confirm payment",
    "routing number", "account number", "pay now", "settle your balance"
  ];

  const ACCOUNT_WARNING_WORDS = [
    "account suspended", "account has been locked", "unusual activity", "unauthorized access",
    "security alert", "suspicious sign-in", "account will be closed", "account deactivated",
    "limited access", "your account is on hold"
  ];

  const DEPARTMENTS = ["Finance", "HR", "Engineering", "Sales", "Executive", "IT", "Customer Support", "Legal"];

  const QUEUE_CAPACITY = 5;
  const LS_QUEUE = "threatlens_queue_v1";
  const LS_CAMPAIGNS = "threatlens_campaigns_v1";
  const LS_COUNTER = "threatlens_case_counter_v1";

  /* ------------------------------------------------------------------ */
  /* Small utilities                                                     */
  /* ------------------------------------------------------------------ */

  // djb2-ish string hash -> unsigned 32-bit int
  function hashString(str) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash) + str.charCodeAt(i);
      hash = hash >>> 0;
    }
    return hash >>> 0;
  }

  // mulberry32 seeded PRNG -> deterministic "randomness" per input
  function mulberry32(seed) {
    let a = seed;
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function clamp(n, min, max) { return Math.max(min, Math.min(max, n)); }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function containsAny(haystack, needles) {
    const lower = haystack.toLowerCase();
    return needles.filter(n => lower.includes(n));
  }

  function extractDomain(addressOrUrl) {
    if (!addressOrUrl) return "";
    let s = addressOrUrl.trim().toLowerCase();
    // email address -> domain
    const atIdx = s.indexOf("@");
    if (atIdx !== -1 && !s.startsWith("http")) {
      s = s.slice(atIdx + 1);
    } else {
      // strip protocol
      s = s.replace(/^https?:\/\//, "");
      s = s.split("/")[0];
      s = s.split("@").pop(); // handle userinfo@host tricks
    }
    s = s.split(":")[0]; // strip port
    return s.replace(/[),.;]+$/, "");
  }

  function isIpHost(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  }

  function extractUrls(text) {
    if (!text) return [];
    const matches = text.match(/https?:\/\/[^\s)>\]]+/gi) || [];
    return matches.map(u => u.replace(/[).,;]+$/, ""));
  }

  // Detect markdown-style [label](url) or "label (url)" mismatches
  function extractLinkPairs(text) {
    const pairs = [];
    const mdRegex = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi;
    let m;
    while ((m = mdRegex.exec(text)) !== null) {
      pairs.push({ label: m[1], url: m[2] });
    }
    const plainRegex = /([A-Za-z0-9.\-]+\.[a-z]{2,})\s*\((https?:\/\/[^\s)]+)\)/gi;
    while ((m = plainRegex.exec(text)) !== null) {
      pairs.push({ label: m[1], url: m[2] });
    }
    return pairs;
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
      }
    }
    return dp[m][n];
  }

  function normalizeHomoglyphs(domain) {
    return domain
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/rn/g, "m")
      .replace(/vv/g, "w")
      .replace(/[-_]/g, "");
  }

  /* ------------------------------------------------------------------ */
  /* Detection: identity / domain                                        */
  /* ------------------------------------------------------------------ */

  function detectBrandMentions(text) {
    const lower = text.toLowerCase();
    return Object.keys(BRANDS).filter(brand => lower.includes(brand));
  }

  function detectLookalikeDomain(domain) {
    if (!domain) return null;
    const bareDomain = domain.replace(/^www\./, "");
    const normalized = normalizeHomoglyphs(bareDomain);

    for (const brand of Object.keys(BRANDS)) {
      const officialDomains = BRANDS[brand];
      for (const official of officialDomains) {
        if (bareDomain === official) return null; // exact legitimate match
        const normalizedOfficial = normalizeHomoglyphs(official);
        const dist = levenshtein(normalized, normalizedOfficial);
        const looksLikeIt = bareDomain.includes(brand) && bareDomain !== official;
        if ((dist > 0 && dist <= 2 && normalized !== normalizedOfficial) || looksLikeIt) {
          return { brand, official, observed: bareDomain, distance: dist };
        }
      }
    }
    return null;
  }

  function detectSuspiciousDomainChars(domain) {
    if (!domain) return [];
    const flags = [];
    const tld = domain.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) flags.push(`uncommon high-risk TLD (.${tld})`);
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount >= 2) flags.push(`${hyphenCount} hyphens in domain`);
    if (/\d{3,}/.test(domain)) flags.push("long numeric sequence in domain");
    const subdomainCount = domain.split(".").length - 2;
    if (subdomainCount >= 3) flags.push(`${subdomainCount} nested subdomains`);
    return flags;
  }

  /* ------------------------------------------------------------------ */
  /* Detection: URL intelligence                                         */
  /* ------------------------------------------------------------------ */

  function analyzeUrls(urls, brandMentions) {
    const findings = { ipUrls: [], suspiciousUrls: [], lookalikeUrlDomains: [] };
    urls.forEach(u => {
      const host = extractDomain(u);
      if (isIpHost(host)) findings.ipUrls.push(u);

      const flags = [];
      if (u.includes("@")) flags.push("embedded @ redirect trick");
      if (/%[0-9a-f]{2}/i.test(u) && (u.match(/%[0-9a-f]{2}/gi) || []).length >= 3) flags.push("heavily percent-encoded path");
      if (u.length > 90) flags.push("abnormally long URL");
      if ((host.split(".").length - 2) >= 3) flags.push("excessive subdomains");
      if (flags.length) findings.suspiciousUrls.push({ url: u, flags });

      const lookalike = detectLookalikeDomain(host);
      if (lookalike) findings.lookalikeUrlDomains.push({ url: u, ...lookalike });
    });
    return findings;
  }

  function analyzeLinkMismatch(pairs) {
    const mismatches = [];
    pairs.forEach(({ label, url }) => {
      const labelLooksLikeDomain = /\.[a-z]{2,}/i.test(label);
      const labelDomain = extractDomain(labelLooksLikeDomain ? label : "");
      const actualDomain = extractDomain(url);
      if (labelLooksLikeDomain && labelDomain && actualDomain && labelDomain !== actualDomain) {
        mismatches.push({ label, displayDomain: labelDomain, actualDomain, url });
      } else {
        // label mentions a brand but actual domain isn't that brand's
        const brandInLabel = detectBrandMentions(label);
        if (brandInLabel.length) {
          const brand = brandInLabel[0];
          const isOfficial = BRANDS[brand].some(d => actualDomain === d || actualDomain.endsWith("." + d));
          if (!isOfficial) {
            mismatches.push({ label, displayDomain: `${brand} (implied)`, actualDomain, url });
          }
        }
      }
    });
    return mismatches;
  }

  /* ------------------------------------------------------------------ */
  /* Demo authentication (SPF / DKIM / DMARC)                             */
  /* ------------------------------------------------------------------ */

  function simulateAuthentication(domain, riskHintScore) {
    // Deterministic per-domain "signal" — NOT a real DNS/auth lookup.
    const rand = mulberry32(hashString("auth::" + domain));
    // Bias failure probability upward when other signals already look bad.
    const bias = clamp(riskHintScore / 140, 0, 0.55);
    const spf = rand() + bias > 0.55 ? "FAIL" : "PASS";
    const dkim = rand() + bias > 0.55 ? "FAIL" : "PASS";
    const dmarc = rand() + bias > 0.6 ? "FAIL" : (rand() > 0.5 ? "PASS" : "NONE");
    return { spf, dkim, dmarc };
  }

  /* ------------------------------------------------------------------ */
  /* Core weighted rule engine                                            */
  /* ------------------------------------------------------------------ */

  const WEIGHTS = {
    LOOKALIKE_DOMAIN: 24,
    SUSPICIOUS_DOMAIN_CHARS: 10,
    IP_URL: 20,
    SUSPICIOUS_URL: 13,
    URL_MISMATCH: 17,
    URGENCY: 9,
    CREDENTIAL_REQUEST: 14,
    PAYMENT_REQUEST: 12,
    ACCOUNT_WARNING: 8,
    AUTH_FAIL_EACH: 6
  };

  /**
   * DEMO RULE ENGINE — replace with Python backend later
   * Pure, deterministic, client-side heuristic scorer.
   * @param {{mode:string, sender:string, subject:string, body:string, url:string}} payload
   */
  function analyzeLocally(payload) {
    const mode = payload.mode || "email";
    const sender = payload.sender || "";
    const subject = payload.subject || "";
    const body = payload.body || "";
    const standaloneUrl = payload.url || "";

    const fullText = [subject, body].join("\n");
    const senderDomain = mode === "url" ? "" : extractDomain(sender);

    const urlsInBody = mode === "url" ? [standaloneUrl] : extractUrls(body);
    const linkPairs = mode === "url" ? [] : extractLinkPairs(body);
    const brandMentions = detectBrandMentions(fullText + " " + sender);

    const signals = []; // { key, label, weight, detail }

    // --- Domain / identity ---
    const lookalike = mode === "url"
      ? detectLookalikeDomain(extractDomain(standaloneUrl))
      : detectLookalikeDomain(senderDomain);
    if (lookalike) {
      signals.push({
        key: "LOOKALIKE_DOMAIN",
        label: "Look-alike / impersonated brand domain",
        weight: WEIGHTS.LOOKALIKE_DOMAIN,
        detail: `"${lookalike.observed}" mimics ${lookalike.brand} (official: ${lookalike.official})`
      });
    }

    const domainForCharCheck = mode === "url" ? extractDomain(standaloneUrl) : senderDomain;
    const suspiciousChars = detectSuspiciousDomainChars(domainForCharCheck);
    if (suspiciousChars.length) {
      signals.push({
        key: "SUSPICIOUS_DOMAIN_CHARS",
        label: "Suspicious domain structure",
        weight: WEIGHTS.SUSPICIOUS_DOMAIN_CHARS,
        detail: suspiciousChars.join(", ")
      });
    }

    // --- URL intelligence ---
    const urlFindings = analyzeUrls(urlsInBody.filter(Boolean), brandMentions);
    if (urlFindings.ipUrls.length) {
      signals.push({
        key: "IP_URL",
        label: "Raw IP address used as link destination",
        weight: WEIGHTS.IP_URL,
        detail: urlFindings.ipUrls.join(", ")
      });
    }
    if (urlFindings.suspiciousUrls.length) {
      signals.push({
        key: "SUSPICIOUS_URL",
        label: "Structurally suspicious URL",
        weight: WEIGHTS.SUSPICIOUS_URL,
        detail: urlFindings.suspiciousUrls.map(f => `${f.url} (${f.flags.join(", ")})`).join(" | ")
      });
    }
    if (urlFindings.lookalikeUrlDomains.length && mode !== "url") {
      // already counted via lookalike domain path for pure URL mode; for email, surface separately
      const extra = urlFindings.lookalikeUrlDomains[0];
      signals.push({
        key: "LOOKALIKE_DOMAIN",
        label: "Look-alike domain in embedded link",
        weight: Math.round(WEIGHTS.LOOKALIKE_DOMAIN * 0.7),
        detail: `Link to "${extra.observed}" mimics ${extra.brand}`
      });
    }

    const mismatches = analyzeLinkMismatch(linkPairs);
    if (mismatches.length) {
      signals.push({
        key: "URL_MISMATCH",
        label: "Display text vs. actual URL mismatch",
        weight: WEIGHTS.URL_MISMATCH,
        detail: mismatches.map(m => `"${m.displayDomain}" → ${m.actualDomain}`).join(" | ")
      });
    }

    // --- Content / social engineering (skipped for standalone URL mode) ---
    let urgencyHits = [], credentialHits = [], paymentHits = [], warningHits = [];
    if (mode !== "url") {
      urgencyHits = containsAny(fullText, URGENCY_WORDS);
      credentialHits = containsAny(fullText, CREDENTIAL_WORDS);
      paymentHits = containsAny(fullText, PAYMENT_WORDS);
      warningHits = containsAny(fullText, ACCOUNT_WARNING_WORDS);

      if (urgencyHits.length) signals.push({ key: "URGENCY", label: "Urgency / pressure language", weight: WEIGHTS.URGENCY, detail: urgencyHits.join(", ") });
      if (credentialHits.length) signals.push({ key: "CREDENTIAL_REQUEST", label: "Credential harvesting language", weight: WEIGHTS.CREDENTIAL_REQUEST, detail: credentialHits.join(", ") });
      if (paymentHits.length) signals.push({ key: "PAYMENT_REQUEST", label: "Payment / financial request", weight: WEIGHTS.PAYMENT_REQUEST, detail: paymentHits.join(", ") });
      if (warningHits.length) signals.push({ key: "ACCOUNT_WARNING", label: "Account warning / scare tactic", weight: WEIGHTS.ACCOUNT_WARNING, detail: warningHits.join(", ") });
    }

    // --- Preliminary score (pre-auth) to bias demo auth simulation ---
    const preAuthScore = signals.reduce((s, sig) => s + sig.weight, 0);

    // --- Demo authentication ---
    const authDomain = mode === "url" ? extractDomain(standaloneUrl) : (senderDomain || "unknown.local");
    const auth = simulateAuthentication(authDomain, preAuthScore);
    const authFailCount = [auth.spf, auth.dkim, auth.dmarc].filter(v => v === "FAIL").length;
    if (authFailCount > 0) {
      signals.push({
        key: "AUTH_FAIL",
        label: "Authentication failure (demo signal)",
        weight: WEIGHTS.AUTH_FAIL_EACH * authFailCount,
        detail: `SPF: ${auth.spf} · DKIM: ${auth.dkim} · DMARC: ${auth.dmarc}`
      });
    }

    // --- Total score ---
    const rawScore = signals.reduce((s, sig) => s + sig.weight, 0);
    const riskScore = clamp(Math.round(rawScore), 0, 100);

    let classification = "SAFE";
    if (riskScore >= 60) classification = "PHISHING";
    else if (riskScore >= 30) classification = "SUSPICIOUS";

    let confidence = "LOW";
    if (signals.length >= 5) confidence = "HIGH";
    else if (signals.length >= 2) confidence = "MEDIUM";

    // --- Evidence payload ---
    const evidence = {
      auth: {
        spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc,
        domain: authDomain
      },
      domain: {
        sender: mode === "email" ? (sender || "—") : "—",
        senderDomain: senderDomain || (mode === "url" ? extractDomain(standaloneUrl) : "—"),
        lookalike: lookalike ? `${lookalike.observed} → mimics ${lookalike.official}` : "No look-alike pattern detected",
        impersonatedBrand: lookalike ? lookalike.brand : (brandMentions[0] || "None referenced"),
        structuralFlags: suspiciousChars.length ? suspiciousChars.join(", ") : "None detected"
      },
      url: {
        count: urlsInBody.filter(Boolean).length,
        ipUrls: urlFindings.ipUrls,
        suspicious: urlFindings.suspiciousUrls,
        mismatches: mismatches
      },
      content: {
        urgency: urgencyHits,
        credential: credentialHits,
        payment: paymentHits,
        warning: warningHits
      }
    };

    // --- Human-readable explanation ---
    const explanation = buildExplanation(signals, classification);

    // --- Campaign correlation ---
    const campaign = correlateCampaign({
      domain: authDomain,
      brand: lookalike ? lookalike.brand : (brandMentions[0] || null),
      classification,
      riskScore
    });

    // --- Blast radius simulation ---
    const blastRadius = simulateBlastRadius(authDomain + "|" + subject, riskScore, campaign);

    // --- SOC priority ---
    const priority = computeSocPriority(riskScore, blastRadius, campaign);

    return {
      classification,
      risk_score: riskScore,
      confidence,
      signals,
      evidence,
      explanation,
      campaign,
      blast_radius: blastRadius,
      priority,
      meta: { mode }
    };
  }

  function buildExplanation(signals, classification) {
    if (!signals.length) {
      return [{
        title: "No material threat signals detected",
        detail: "Sender domain, embedded URLs, and message language did not match any known phishing patterns in the local rule set."
      }];
    }

    const groupMap = {
      LOOKALIKE_DOMAIN: "Identity deception",
      SUSPICIOUS_DOMAIN_CHARS: "Domain anomaly",
      IP_URL: "URL deception",
      SUSPICIOUS_URL: "URL deception",
      URL_MISMATCH: "URL deception",
      URGENCY: "Social engineering",
      CREDENTIAL_REQUEST: "Credential risk",
      PAYMENT_REQUEST: "Financial fraud risk",
      ACCOUNT_WARNING: "Social engineering",
      AUTH_FAIL: "Authentication failure (demo signal)"
    };

    return signals
      .sort((a, b) => b.weight - a.weight)
      .map(sig => ({
        title: groupMap[sig.key] || sig.label,
        detail: `${sig.label}: ${sig.detail} (+${sig.weight} pts)`
      }));
  }

  /* ------------------------------------------------------------------ */
  /* Campaign correlation (persisted)                                     */
  /* ------------------------------------------------------------------ */

  function loadCampaigns() {
    try {
      return JSON.parse(localStorage.getItem(LS_CAMPAIGNS)) || {};
    } catch (e) { return {}; }
  }

  function saveCampaigns(campaigns) {
    try { localStorage.setItem(LS_CAMPAIGNS, JSON.stringify(campaigns)); } catch (e) { /* storage unavailable */ }
  }

  function correlateCampaign({ domain, brand, classification, riskScore }) {
    if (classification === "SAFE") {
      return { active: false, id: null, message: "No active campaign correlation — message did not meet the suspicious threshold." };
    }

    const key = `${brand || "unknown"}::${domain}`;
    const campaigns = loadCampaigns();
    const id = "CMP-" + hashString(key).toString(16).toUpperCase().slice(0, 6);

    const now = new Date().toISOString();
    let record = campaigns[id];
    if (!record) {
      record = {
        id,
        brand: brand || "Unspecified",
        domain,
        relatedCases: 0,
        firstObserved: now,
        lastObserved: now,
        recipients: 0,
        departments: [],
        status: "MONITORING"
      };
    }

    record.relatedCases += 1;
    record.lastObserved = now;
    record.status = record.relatedCases >= 3 ? "ACTIVE — SPREADING" : (riskScore >= 60 ? "ACTIVE" : "MONITORING");

    // simulate additional recipients / departments touched by this campaign over time
    const rand = mulberry32(hashString(key + record.relatedCases));
    const newRecipients = 2 + Math.floor(rand() * 6);
    record.recipients += newRecipients;
    const deptPool = [...DEPARTMENTS];
    const touchedCount = 1 + Math.floor(rand() * 3);
    for (let i = 0; i < touchedCount; i++) {
      const d = deptPool[Math.floor(rand() * deptPool.length)];
      if (!record.departments.includes(d)) record.departments.push(d);
    }

    campaigns[id] = record;
    saveCampaigns(campaigns);

    return {
      active: true,
      id: record.id,
      brand: record.brand,
      relatedCases: record.relatedCases,
      recipients: record.recipients,
      departments: record.departments,
      firstObserved: record.firstObserved,
      lastObserved: record.lastObserved,
      status: record.status
    };
  }

  /* ------------------------------------------------------------------ */
  /* Blast radius simulation                                             */
  /* ------------------------------------------------------------------ */

  function simulateBlastRadius(seedStr, riskScore, campaign) {
    const rand = mulberry32(hashString("blast::" + seedStr));
    if (riskScore < 30) {
      return {
        exposed: 1, delivered: 1, opened: rand() > 0.5 ? 1 : 0, clicked: 0,
        credentialAttempts: 0, departments: [], highRiskUsers: 0
      };
    }

    const severityFactor = riskScore / 100;
    const baseExposed = campaign && campaign.active ? Math.max(campaign.recipients, 4) : 4 + Math.floor(rand() * 10);
    const exposed = clamp(Math.round(baseExposed * (0.7 + severityFactor)), 3, 480);
    const delivered = Math.round(exposed * (0.9 + rand() * 0.1));
    const opened = Math.round(delivered * (0.35 + severityFactor * 0.4));
    const clicked = Math.round(opened * (0.25 + severityFactor * 0.45));
    const credentialAttempts = Math.round(clicked * (0.15 + severityFactor * 0.4));
    const highRiskUsers = Math.max(credentialAttempts, Math.round(clicked * 0.3));

    const departments = campaign && campaign.active && campaign.departments.length
      ? campaign.departments
      : (() => {
          const pool = [...DEPARTMENTS];
          const count = 1 + Math.floor(rand() * 3);
          const picked = [];
          for (let i = 0; i < count; i++) {
            const d = pool[Math.floor(rand() * pool.length)];
            if (!picked.includes(d)) picked.push(d);
          }
          return picked;
        })();

    return { exposed, delivered, opened, clicked, credentialAttempts, departments, highRiskUsers };
  }

  /* ------------------------------------------------------------------ */
  /* SOC priority computation                                             */
  /* ------------------------------------------------------------------ */

  function computeSocPriority(riskScore, blastRadius, campaign) {
    const exposureScore = clamp(Math.round((blastRadius.exposed / 100) * 100), 0, 100);
    const campaignScore = campaign && campaign.active
      ? clamp(20 + campaign.relatedCases * 15, 0, 100)
      : 0;

    const score = clamp(Math.round(riskScore * 0.5 + exposureScore * 0.3 + campaignScore * 0.2), 0, 100);

    let level = "LOW";
    let action = "No action required. Log for baseline telemetry.";
    if (score >= 85) {
      level = "CRITICAL";
      action = "Escalate immediately: isolate affected mailboxes, block sender domain network-wide, force credential reset for exposed users.";
    } else if (score >= 65) {
      level = "HIGH";
      action = "Assign to on-call analyst within 30 minutes. Block malicious URLs/domain and notify exposed departments.";
    } else if (score >= 40) {
      level = "MEDIUM";
      action = "Queue for analyst review within shift. Monitor for additional related reports.";
    }

    return {
      score,
      level,
      action,
      breakdown: { riskScore, exposureScore, campaignScore }
    };
  }

  /* ------------------------------------------------------------------ */
  /* analyzeWithBackend — placeholder for future Python service          */
  /* ------------------------------------------------------------------ */

  /**
   * TODO: Replace with a real call to the Python backend, e.g.:
   *   const res = await fetch("/api/analyze", {
   *     method: "POST",
   *     headers: { "Content-Type": "application/json" },
   *     body: JSON.stringify(payload)
   *   });
   *   return res.json();
   *
   * The backend is expected to run full multi-signal detection (real DNS/
   * SPF/DKIM/DMARC lookups, URL sandboxing, brand-similarity models,
   * campaign clustering against PostgreSQL) and return a result object
   * shaped exactly like analyzeLocally()'s return value:
   *   { classification, risk_score, confidence, signals, evidence,
   *     explanation, campaign, blast_radius, priority }
   *
   * Until that backend exists, this simply delegates to the local demo
   * rule engine after a short simulated network delay so the pipeline
   * animation has something to animate against.
   */
  async function analyzeWithBackend(payload) {
    // TODO: swap this block for the real fetch() call above.
    await new Promise(resolve => setTimeout(resolve, 120));
    return analyzeLocally(payload);
  }

  /* ------------------------------------------------------------------ */
  /* .eml parsing (very small RFC822-ish subset)                         */
  /* ------------------------------------------------------------------ */

  function parseEml(rawText) {
    const lines = rawText.split(/\r?\n/);
    let from = "", subject = "";
    let i = 0;
    for (; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() === "") { i++; break; } // end of headers
      const fromMatch = line.match(/^From:\s*(.*)$/i);
      const subjMatch = line.match(/^Subject:\s*(.*)$/i);
      if (fromMatch) from = fromMatch[1].trim();
      if (subjMatch) subject = subjMatch[1].trim();
    }
    const body = lines.slice(i).join("\n").trim();

    // Extract bare email address from "Display Name <addr@domain>" format
    const addrMatch = from.match(/<([^>]+)>/);
    const senderAddress = addrMatch ? addrMatch[1] : from;

    return {
      sender: senderAddress || "unknown@unknown",
      subject: subject || "(no subject found)",
      body: body || rawText.trim()
    };
  }

  /* ------------------------------------------------------------------ */
  /* Investigation Queue (persisted)                                     */
  /* ------------------------------------------------------------------ */

  function loadQueue() {
    try { return JSON.parse(localStorage.getItem(LS_QUEUE)) || []; } catch (e) { return []; }
  }

  function saveQueue(queue) {
    try { localStorage.setItem(LS_QUEUE, JSON.stringify(queue)); } catch (e) { /* storage unavailable */ }
  }

  function nextCaseId() {
    let n = 0;
    try { n = parseInt(localStorage.getItem(LS_COUNTER) || "0", 10) || 0; } catch (e) { /* ignore */ }
    n += 1;
    try { localStorage.setItem(LS_COUNTER, String(n)); } catch (e) { /* ignore */ }
    const d = new Date();
    const datePart = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}${String(d.getDate()).padStart(2, "0")}`;
    return `TL-${datePart}-${String(n).padStart(4, "0")}`;
  }

  function addToQueue(caseRecord) {
    if (caseRecord.risk_score < 30) return loadQueue(); // SAFE cases don't need SOC investigation

    let queue = loadQueue();
    queue.push(caseRecord);
    queue.sort((a, b) => b.priorityScore - a.priorityScore);
    if (queue.length > QUEUE_CAPACITY) {
      queue = queue.slice(0, QUEUE_CAPACITY);
    }
    saveQueue(queue);
    return queue;
  }

  function cycleStatus(status) {
    if (status === "NEW") return "INVESTIGATING";
    if (status === "INVESTIGATING") return "RESOLVED";
    return "RESOLVED";
  }

  /* ------------------------------------------------------------------ */
  /* DOM wiring                                                           */
  /* ------------------------------------------------------------------ */

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    wireTabs();
    wireEmlUpload();
    wireAnalyzeButton();
    wireResetButton();
    wireQueueDelegation();
    renderQueue();
  }

  function wireTabs() {
    const tabs = document.querySelectorAll(".tab");
    tabs.forEach(tab => {
      tab.addEventListener("click", () => {
        tabs.forEach(t => t.classList.remove("is-active"));
        document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("is-active"));
        tab.classList.add("is-active");
        document.querySelector(`.tab-pane[data-pane="${tab.dataset.tab}"]`).classList.add("is-active");
        setError("");
      });
    });
  }

  function activeTab() {
    return document.querySelector(".tab.is-active").dataset.tab;
  }

  function wireEmlUpload() {
    const input = document.getElementById("in-eml");
    const filenameEl = document.getElementById("eml-filename");
    input.addEventListener("change", () => {
      if (!input.files || !input.files[0]) {
        filenameEl.textContent = "No file selected — headers and body will be parsed automatically.";
        return;
      }
      const file = input.files[0];
      filenameEl.textContent = `Selected: ${file.name} (${Math.round(file.size / 1024)} KB)`;
    });
  }

  function setError(msg) {
    document.getElementById("input-error").textContent = msg || "";
  }

  function wireAnalyzeButton() {
    document.getElementById("btn-analyze").addEventListener("click", handleAnalyzeClick);
  }

  async function handleAnalyzeClick() {
    const mode = activeTab();
    setError("");

    let payload = { mode };

    if (mode === "email") {
      const sender = document.getElementById("in-sender").value.trim();
      const subject = document.getElementById("in-subject").value.trim();
      const body = document.getElementById("in-body").value.trim();
      if (!sender || !subject || !body) {
        setError("Sender, subject, and body are all required for email analysis.");
        return;
      }
      if (!sender.includes("@")) {
        setError("Sender must be a valid email address (e.g. user@domain.com).");
        return;
      }
      payload = { mode, sender, subject, body };
    } else if (mode === "url") {
      const url = document.getElementById("in-url").value.trim();
      if (!url) {
        setError("Enter a URL to analyze.");
        return;
      }
      if (!/^https?:\/\//i.test(url)) {
        setError("URL must start with http:// or https://");
        return;
      }
      payload = { mode, url, subject: "", body: "", sender: "" };
    } else if (mode === "eml") {
      const fileInput = document.getElementById("in-eml");
      if (!fileInput.files || !fileInput.files[0]) {
        setError("Select a .eml file to upload.");
        return;
      }
      try {
        const text = await fileInput.files[0].text();
        const parsed = parseEml(text);
        payload = { mode: "email", ...parsed };
      } catch (e) {
        setError("Could not read that file. Please upload a plain-text .eml file.");
        return;
      }
    }

    await runAnalysis(payload);
  }

  async function runAnalysis(payload) {
    const analyzeBtn = document.getElementById("btn-analyze");
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "ANALYZING…";

    document.getElementById("panel-pipeline").classList.remove("is-hidden");
    document.getElementById("results").classList.add("is-hidden");
    document.getElementById("pipeline-status").textContent = "RUNNING";
    resetPipelineUI();

    // Kick off the backend-shaped call while we animate the pipeline.
    const resultPromise = analyzeWithBackend(payload);

    await animatePipeline();

    const result = await resultPromise;

    document.getElementById("pipeline-status").textContent = "COMPLETE";
    renderResults(payload, result);

    const caseId = nextCaseId();
    document.getElementById("case-id-tag").textContent = `CASE ${caseId}`;

    const queueRecord = {
      caseId,
      campaignId: result.campaign.active ? result.campaign.id : "—",
      priorityLevel: result.priority.level,
      priorityScore: result.priority.score,
      exposure: result.blast_radius.exposed,
      riskScore: result.risk_score,
      classification: result.classification,
      status: "NEW",
      timestamp: new Date().toISOString()
    };
    const queue = addToQueue(queueRecord);
    renderQueue(queue);

    document.getElementById("results").classList.remove("is-hidden");
    document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });

    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = '<span class="btn__icon">▣</span> ANALYZE THREAT';
  }

  function resetPipelineUI() {
    document.querySelectorAll(".pipeline__stage").forEach(el => {
      el.classList.remove("is-active", "is-done");
    });
  }

  function animatePipeline() {
    return new Promise(resolve => {
      let idx = 0;
      const stages = document.querySelectorAll(".pipeline__stage");
      function step() {
        if (idx > 0) stages[idx - 1].classList.remove("is-active");
        if (idx > 0) stages[idx - 1].classList.add("is-done");
        if (idx >= stages.length) { resolve(); return; }
        stages[idx].classList.add("is-active");
        idx++;
        setTimeout(step, 220);
      }
      step();
    });
  }

  /* ------------------------------------------------------------------ */
  /* Rendering results                                                    */
  /* ------------------------------------------------------------------ */

  function renderResults(payload, result) {
    renderVerdict(result);
    renderEvidence(result);
    renderExplanation(result);
    renderCampaign(result);
    renderBlastRadius(result);
    renderPriority(result);
  }

  function renderVerdict(result) {
    const classEl = document.getElementById("v-classification");
    classEl.textContent = result.classification;
    classEl.className = "verdict-classification__value " + ({
      SAFE: "is-safe", SUSPICIOUS: "is-suspicious", PHISHING: "is-phishing"
    })[result.classification];

    const riskbar = document.getElementById("v-riskbar");
    riskbar.style.width = result.risk_score + "%";
    riskbar.style.background = result.risk_score >= 60 ? "var(--phishing)" : result.risk_score >= 30 ? "var(--suspicious)" : "var(--safe)";
    document.getElementById("v-risk").textContent = `${result.risk_score}/100`;

    const confEl = document.getElementById("v-confidence");
    confEl.textContent = result.confidence;
    confEl.className = "pill " + ({ LOW: "is-low", MEDIUM: "is-medium", HIGH: "is-high" })[result.confidence];

    const prioEl = document.getElementById("v-priority");
    prioEl.textContent = result.priority.level;
    prioEl.className = "pill " + ({ LOW: "is-low", MEDIUM: "is-medium", HIGH: "is-high", CRITICAL: "is-critical" })[result.priority.level];
  }

  function kvRow(key, value, tone) {
    const toneClass = tone ? ` is-${tone}` : "";
    return `<div class="kv-row"><span class="kv-row__key">${escapeHtml(key)}</span><span class="kv-row__val${toneClass}">${escapeHtml(value)}</span></div>`;
  }

  function renderEvidence(result) {
    const ev = result.evidence;

    document.getElementById("ev-auth").innerHTML = [
      kvRow("SPF", ev.auth.spf, ev.auth.spf === "PASS" ? "pass" : "fail"),
      kvRow("DKIM", ev.auth.dkim, ev.auth.dkim === "PASS" ? "pass" : "fail"),
      kvRow("DMARC", ev.auth.dmarc, ev.auth.dmarc === "PASS" ? "pass" : (ev.auth.dmarc === "FAIL" ? "fail" : "flag")),
      kvRow("Evaluated domain", ev.auth.domain, "")
    ].join("");

    document.getElementById("ev-domain").innerHTML = [
      kvRow("Sender", ev.domain.sender || "—", ""),
      kvRow("Sender domain", ev.domain.senderDomain || "—", ""),
      kvRow("Look-alike check", ev.domain.lookalike, ev.domain.lookalike.startsWith("No") ? "" : "flag"),
      kvRow("Impersonated brand", ev.domain.impersonatedBrand, ev.domain.impersonatedBrand === "None referenced" ? "" : "flag"),
      kvRow("Structural flags", ev.domain.structuralFlags, ev.domain.structuralFlags === "None detected" ? "" : "flag")
    ].join("");

    const urlRows = [];
    urlRows.push(kvRow("URLs found", String(ev.url.count), ""));
    if (ev.url.ipUrls.length) urlRows.push(kvRow("IP-based URL", ev.url.ipUrls.join(", "), "fail"));
    if (ev.url.suspicious.length) {
      ev.url.suspicious.forEach(s => urlRows.push(kvRow("Suspicious URL", `${s.url} — ${s.flags.join(", ")}`, "flag")));
    }
    if (ev.url.mismatches.length) {
      ev.url.mismatches.forEach(m => urlRows.push(kvRow("Display vs actual", `"${m.displayDomain}" shown, links to ${m.actualDomain}`, "fail")));
    }
    if (ev.url.count === 0) urlRows.push(kvRow("Assessment", "No URLs present in message", ""));
    document.getElementById("ev-url").innerHTML = urlRows.join("");

    const contentRows = [];
    contentRows.push(kvRow("Urgency language", ev.content.urgency.length ? ev.content.urgency.join(", ") : "None detected", ev.content.urgency.length ? "flag" : ""));
    contentRows.push(kvRow("Credential request", ev.content.credential.length ? ev.content.credential.join(", ") : "None detected", ev.content.credential.length ? "fail" : ""));
    contentRows.push(kvRow("Payment request", ev.content.payment.length ? ev.content.payment.join(", ") : "None detected", ev.content.payment.length ? "flag" : ""));
    contentRows.push(kvRow("Account warning", ev.content.warning.length ? ev.content.warning.join(", ") : "None detected", ev.content.warning.length ? "flag" : ""));
    document.getElementById("ev-content").innerHTML = contentRows.join("");
  }

  function renderExplanation(result) {
    const list = document.getElementById("reason-list");
    document.getElementById("explain-count").textContent = `${result.explanation.length} reason${result.explanation.length === 1 ? "" : "s"}`;
    if (!result.signals.length) {
      list.innerHTML = `<li class="reason-list--empty">No material threat signals detected in this input.</li>`;
      return;
    }
    list.innerHTML = result.explanation.map((r, idx) => `
      <li>
        <span class="reason-list__badge">${idx + 1}</span>
        <span class="reason-list__body">
          <span class="reason-list__title">${escapeHtml(r.title)}</span>
          <span class="reason-list__detail">${escapeHtml(r.detail)}</span>
        </span>
      </li>
    `).join("");
  }

  function campaignCell(label, value) {
    return `<div class="campaign-cell"><span class="campaign-cell__label">${escapeHtml(label)}</span><span class="campaign-cell__value">${escapeHtml(value)}</span></div>`;
  }

  function renderCampaign(result) {
    const c = result.campaign;
    const statusEl = document.getElementById("campaign-status");
    const grid = document.getElementById("campaign-grid");

    if (!c.active) {
      statusEl.textContent = "NO CORRELATION";
      grid.innerHTML = campaignCell("Status", c.message);
      return;
    }

    statusEl.textContent = c.status;
    grid.innerHTML = [
      campaignCell("Campaign ID", c.id),
      campaignCell("Impersonated brand", c.brand),
      campaignCell("Related cases", String(c.relatedCases)),
      campaignCell("Recipients targeted", String(c.recipients)),
      campaignCell("First observed", new Date(c.firstObserved).toLocaleString()),
      campaignCell("Latest observed", new Date(c.lastObserved).toLocaleString()),
      campaignCell("Departments touched", c.departments.join(", ") || "—"),
      campaignCell("Status", c.status)
    ].join("");
  }

  function blastCell(value, label) {
    return `<div class="blast-cell"><span class="blast-cell__value">${escapeHtml(String(value))}</span><span class="blast-cell__label">${escapeHtml(label)}</span></div>`;
  }

  function renderBlastRadius(result) {
    const b = result.blast_radius;
    document.getElementById("blast-grid").innerHTML = [
      blastCell(b.exposed, "Employees exposed"),
      blastCell(b.delivered, "Emails delivered"),
      blastCell(b.opened, "Opened"),
      blastCell(b.clicked, "Clicked link"),
      blastCell(b.credentialAttempts, "Credential attempts")
    ].join("");

    const deptRow = document.getElementById("blast-departments");
    if (!b.departments.length) {
      deptRow.innerHTML = `<span class="chip">No departments affected</span>`;
    } else {
      deptRow.innerHTML = b.departments.map(d => `<span class="chip is-risk">${escapeHtml(d)}</span>`).join("")
        + `<span class="chip">${b.highRiskUsers} high-risk user${b.highRiskUsers === 1 ? "" : "s"}</span>`;
    }
  }

  function renderPriority(result) {
    const p = result.priority;
    document.getElementById("priority-formula").innerHTML = `
      <span class="term">Risk severity<small>${p.breakdown.riskScore} × 0.5</small></span>
      <span class="op">+</span>
      <span class="term">Exposure<small>${p.breakdown.exposureScore} × 0.3</small></span>
      <span class="op">+</span>
      <span class="term">Campaign spread<small>${p.breakdown.campaignScore} × 0.2</small></span>
      <span class="op">=</span>
      <span class="term result">${p.score} / 100</span>
    `;
    const levelEl = document.getElementById("priority-level");
    levelEl.textContent = `${p.level} PRIORITY`;
    levelEl.className = "priority-outcome__level " + ({ LOW: "is-low", MEDIUM: "is-medium", HIGH: "is-high", CRITICAL: "is-critical" })[p.level];
    document.getElementById("priority-action").textContent = p.action;
  }

  /* ------------------------------------------------------------------ */
  /* Queue rendering                                                      */
  /* ------------------------------------------------------------------ */

  function renderQueue(queueArg) {
    const queue = queueArg || loadQueue();
    document.getElementById("queue-capacity").textContent = `${queue.length} / ${QUEUE_CAPACITY} analyst slots used`;
    const body = document.getElementById("queue-body");

    if (!queue.length) {
      body.innerHTML = `<tr class="queue-empty-row"><td colspan="7">No active cases. Analyze a threat to populate the queue.</td></tr>`;
      return;
    }

    const priorityClass = { LOW: "is-low", MEDIUM: "is-medium", HIGH: "is-high", CRITICAL: "is-critical" };
    const statusClass = { NEW: "", INVESTIGATING: "is-investigating", RESOLVED: "is-resolved" };

    body.innerHTML = queue.map(row => `
      <tr data-case-id="${escapeHtml(row.caseId)}">
        <td><span class="queue-priority-flag ${priorityClass[row.priorityLevel]}">${row.priorityLevel} · ${row.priorityScore}</span></td>
        <td><span class="queue-case-id">${escapeHtml(row.caseId)}</span></td>
        <td>${escapeHtml(row.campaignId)}</td>
        <td>${row.exposure} exposed</td>
        <td>${row.riskScore}/100 · ${escapeHtml(row.classification)}</td>
        <td><button class="queue-status-btn ${statusClass[row.status]}" data-action="cycle-status">${row.status}</button></td>
        <td><button class="queue-investigate-btn" data-action="investigate">Investigate →</button></td>
      </tr>
    `).join("");
  }

  function wireQueueDelegation() {
    document.getElementById("queue-body").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-action]");
      if (!btn) return;
      const row = btn.closest("tr");
      const caseId = row.dataset.caseId;
      let queue = loadQueue();
      const record = queue.find(r => r.caseId === caseId);
      if (!record) return;

      if (btn.dataset.action === "cycle-status") {
        record.status = cycleStatus(record.status);
        saveQueue(queue);
        renderQueue(queue);
      } else if (btn.dataset.action === "investigate") {
        alert(
          `INVESTIGATING ${record.caseId}\n\n` +
          `Campaign: ${record.campaignId}\n` +
          `Classification: ${record.classification}\n` +
          `Risk score: ${record.riskScore}/100\n` +
          `Priority: ${record.priorityLevel} (${record.priorityScore}/100)\n` +
          `Employees exposed: ${record.exposure}\n\n` +
          `Recommended: pull full case detail from the analysis panel above, confirm blast radius, and action per SOC priority guidance.`
        );
        if (record.status === "NEW") {
          record.status = "INVESTIGATING";
          saveQueue(queue);
          renderQueue(queue);
        }
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Reset                                                                */
  /* ------------------------------------------------------------------ */

  function wireResetButton() {
    document.getElementById("btn-reset").addEventListener("click", () => {
      if (!confirm("Reset ThreatLens workspace? This clears the investigation queue and campaign correlation history stored in this browser.")) return;
      try {
        localStorage.removeItem(LS_QUEUE);
        localStorage.removeItem(LS_CAMPAIGNS);
        localStorage.removeItem(LS_COUNTER);
      } catch (e) { /* storage unavailable */ }

      document.getElementById("in-sender").value = "";
      document.getElementById("in-subject").value = "";
      document.getElementById("in-body").value = "";
      document.getElementById("in-url").value = "";
      document.getElementById("in-eml").value = "";
      document.getElementById("eml-filename").textContent = "No file selected — headers and body will be parsed automatically.";
      setError("");

      document.getElementById("panel-pipeline").classList.add("is-hidden");
      document.getElementById("results").classList.add("is-hidden");
      resetPipelineUI();
      renderQueue([]);
    });
  }

  // Expose for console/testing/future backend wiring.
  window.ThreatLens = { analyzeLocally, analyzeWithBackend };

})();
