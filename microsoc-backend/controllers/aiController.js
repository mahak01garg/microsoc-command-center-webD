const crypto = require('crypto');

const AI_PROVIDER = (process.env.AI_PROVIDER || (process.env.GEMINI_API_KEY ? 'gemini' : 'openai')).toLowerCase();
const AI_MODEL = process.env.AI_MODEL || (AI_PROVIDER === 'gemini' ? 'gemini-2.0-flash' : 'gpt-4o-mini');
const AI_BASE_URL = (process.env.AI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, '');
const AI_API_KEY = process.env.AI_API_KEY || process.env.OPENAI_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_BASE_URL = (process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, '');

function redactSensitive(input) {
  const sensitiveKeys = /password|passwd|pwd|token|api[_-]?key|secret/i;
  const emailPattern = /([\w.+-]+)@([\w.-]+\.[A-Za-z]{2,})/g;

  function clean(value, key = '') {
    if (sensitiveKeys.test(key)) return '[redacted]';
    if (Array.isArray(value)) return value.map(item => clean(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value).map(([entryKey, entryValue]) => [entryKey, clean(entryValue, entryKey)])
      );
    }
    if (typeof value === 'string') {
      return value.replace(emailPattern, '$1@[redacted-domain]');
    }
    return value;
  }

  return clean(input || {});
}

function severityScore(severity) {
  const scores = { critical: 95, high: 78, medium: 52, low: 25 };
  return scores[String(severity || '').toLowerCase()] || 45;
}

function attackPlaybook(type = '') {
  const key = String(type).toLowerCase();
  if (key.includes('sql')) {
    return {
      mitre: ['T1190 Exploit Public-Facing Application', 'T1059 Command and Scripting Interpreter'],
      actions: ['Block source IP at WAF/firewall', 'Review vulnerable route and parameterized queries', 'Check database error logs and privilege boundaries'],
      containment: ['Enable SQLi WAF rule in block mode', 'Temporarily rate-limit affected endpoint']
    };
  }
  if (key.includes('xss')) {
    return {
      mitre: ['T1189 Drive-by Compromise', 'T1059.007 JavaScript'],
      actions: ['Sanitize reflected/stored inputs', 'Tighten Content Security Policy', 'Review affected user sessions for hijack indicators'],
      containment: ['Invalidate suspicious sessions', 'Deploy CSP report-only then enforce']
    };
  }
  if (key.includes('brute')) {
    return {
      mitre: ['T1110 Brute Force', 'T1078 Valid Accounts'],
      actions: ['Enable MFA for targeted accounts', 'Apply adaptive rate limiting', 'Review failed-login source clusters'],
      containment: ['Lock targeted accounts after verification', 'Block repeated sources temporarily']
    };
  }
  if (key.includes('port') || key.includes('scan')) {
    return {
      mitre: ['T1046 Network Service Discovery', 'T1595 Active Scanning'],
      actions: ['Confirm exposed ports are business-required', 'Tune IDS scan thresholds', 'Harden services discovered externally'],
      containment: ['Block scanner IP ranges', 'Restrict administrative ports to VPN']
    };
  }
  if (key.includes('ddos')) {
    return {
      mitre: ['T1498 Network Denial of Service'],
      actions: ['Enable upstream DDoS protection', 'Rate-limit noisy paths', 'Inspect traffic by ASN/country/user-agent'],
      containment: ['Activate CDN challenge mode', 'Drop malformed packets at edge']
    };
  }
  if (key.includes('malware') || key.includes('phishing')) {
    return {
      mitre: ['T1566 Phishing', 'T1204 User Execution'],
      actions: ['Isolate impacted host/mailbox', 'Collect file hash and sender metadata', 'Run endpoint scan and mailbox search'],
      containment: ['Quarantine matching messages/files', 'Reset impacted credentials']
    };
  }
  return {
    mitre: ['T1082 System Information Discovery', 'T1071 Application Layer Protocol'],
    actions: ['Correlate with nearby auth/network events', 'Confirm whether activity was blocked', 'Add temporary monitoring rule for repeat sources'],
    containment: ['Increase logging on target asset', 'Block source if repeated or high severity']
  };
}

function fallbackLogExplanation(log = {}) {
  const playbook = attackPlaybook(log.attackType || log.description);
  const blockedText = log.isBlocked ? 'The control appears to have blocked the event.' : 'The event still looks active or unblocked.';
  return {
    title: `${log.attackType || 'Suspicious activity'} against ${log.targetSystem || 'unknown target'}`,
    summary: `${log.sourceIP || 'Unknown source'} triggered a ${log.severity || 'medium'} severity event. ${blockedText}`,
    risk: severityScore(log.severity),
    likelyIntent: `Likely intent: ${log.attackType || 'reconnaissance or exploitation'} based on the event description.`,
    recommendedActions: playbook.actions,
    containment: playbook.containment,
    mitre: playbook.mitre,
    evidenceNeeded: ['Raw request payload', 'Authentication events around same timestamp', 'Firewall/WAF decision logs', 'Target host process/network telemetry']
  };
}

function fallbackIncidentTriage(incident = {}) {
  const baseScore = severityScore(incident.severity);
  const logBoost = Math.min(Number(incident.logs || 0), 40);
  const priorityScore = Math.min(100, baseScore + Math.round(logBoost / 3));
  const playbook = attackPlaybook(`${incident.title || ''} ${incident.description || ''}`);
  return {
    severity: incident.severity || (priorityScore > 85 ? 'critical' : priorityScore > 65 ? 'high' : 'medium'),
    priorityScore,
    summary: `${incident.title || 'Security incident'} should be handled as priority ${priorityScore}/100 because it combines severity, related log volume, and target exposure.`,
    businessImpact: priorityScore > 80 ? 'Potential service compromise or credential exposure if not contained quickly.' : 'Limited but meaningful risk; monitor for repeat activity and lateral movement.',
    recommendedActions: playbook.actions,
    containment: playbook.containment,
    mitre: playbook.mitre,
    evidenceNeeded: ['First seen / last seen timestamps', 'Impacted assets and owners', 'Source reputation', 'Whether any control blocked the attack']
  };
}

function fallbackReport(payload = {}) {
  const analytics = payload.analytics || {};
  const patterns = analytics.patterns || [];
  const anomalies = analytics.anomalies || [];
  const riskScore = Number(payload.riskScore || analytics.riskScore || 68);
  const topPattern = patterns[0]?.name || 'recurring attack pattern';
  return {
    title: 'AI SOC Executive Summary',
    riskScore,
    confidence: 86,
    summary: `MicroSOC currently shows a ${riskScore >= 75 ? 'high' : riskScore >= 50 ? 'moderate' : 'low'} operating risk. The strongest signal is ${topPattern}, with ${anomalies.length || 3} anomaly groups needing review.`,
    keyFindings: [
      `${patterns.length || 4} behavioral patterns are active in the current analytics window.`,
      `${anomalies.length || 3} anomalies suggest possible attacker experimentation or control bypass attempts.`,
      'Critical assets should receive stricter rate limiting, WAF rules, and authentication monitoring.'
    ],
    recommendedActions: [
      'Triage critical/high events first and convert confirmed cases into incidents.',
      'Enable stricter WAF signatures for the top attack family.',
      'Review geo/source clusters and add temporary deny or challenge rules.',
      'Export this report daily for shift handover and audit trail.'
    ],
    watchlist: ['Repeated source IPs', 'Failed login bursts', 'Unblocked high severity logs', 'New anomalous user agents']
  };
}

function fallbackChat(message = '', context = {}) {
  const normalized = String(message).toLowerCase();
  if (normalized.includes('priority') || normalized.includes('first')) {
    return 'Start with critical/high unblocked events, then incidents with many related logs, then repeated sources. Convert anything with confirmed impact into an incident and document containment.';
  }
  if (normalized.includes('report')) {
    return 'Use Analytics -> Generate Insights. It will produce a SOC summary, key findings, recommended actions, and a watchlist from the current telemetry.';
  }
  if (normalized.includes('password') || normalized.includes('approval')) {
    return 'Account approvals and password resets should stay admin-controlled. Check pending users first, approve only known analysts, and keep OTP expiry short.';
  }
  return `I reviewed the available MicroSOC context (${Object.keys(context || {}).join(', ') || 'no extra context'}). Recommended next step: triage open critical/high incidents, inspect related logs, and apply temporary containment before permanent remediation.`;
}

async function callAiJson(systemPrompt, userPayload, fallbackFactory) {
  const safePayload = redactSensitive(userPayload);
  const hasProviderKey = AI_PROVIDER === 'gemini' ? GEMINI_API_KEY : AI_API_KEY;

  if (!hasProviderKey) {
    return { mode: 'fallback', data: fallbackFactory(safePayload) };
  }

  try {
    const content = AI_PROVIDER === 'gemini'
      ? await callGeminiJson(systemPrompt, safePayload)
      : await callOpenAiJson(systemPrompt, safePayload);

    if (!content) throw new Error('AI provider returned empty content');

    return { mode: 'ai', data: JSON.parse(content) };
  } catch (error) {
    console.error('AI provider fallback:', error.message);
    return { mode: 'fallback', data: fallbackFactory(safePayload) };
  }
}

async function callOpenAiJson(systemPrompt, safePayload) {
  const response = await fetch(`${AI_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${AI_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: AI_MODEL,
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: `${systemPrompt}\nReturn only valid JSON.` },
        { role: 'user', content: JSON.stringify(safePayload) }
      ]
    })
  });

  if (!response.ok) {
    throw new Error(`OpenAI provider returned ${response.status}`);
  }

  const body = await response.json();
  return body.choices?.[0]?.message?.content;
}

async function callGeminiJson(systemPrompt, safePayload) {
  const model = encodeURIComponent(AI_MODEL);
  const url = `${GEMINI_BASE_URL}/models/${model}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
  const prompt = [
    systemPrompt,
    'Return only valid JSON. Do not wrap the JSON in Markdown.',
    JSON.stringify(safePayload)
  ].join('\n\n');

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      contents: [
        {
          role: 'user',
          parts: [{ text: prompt }]
        }
      ],
      generationConfig: {
        temperature: 0.2,
        responseMimeType: 'application/json'
      }
    })
  });

  if (!response.ok) {
    throw new Error(`Gemini provider returned ${response.status}`);
  }

  const body = await response.json();
  return body.candidates?.[0]?.content?.parts
    ?.map(part => part.text || '')
    .join('')
    .trim();
}

exports.explainLog = async (req, res) => {
  const result = await callAiJson(
    'You are a senior SOC analyst. Explain a security log with concise risk, likely intent, MITRE mapping, containment, and evidence needed.',
    req.body.log || req.body,
    fallbackLogExplanation
  );

  res.json({ success: true, ...result });
};

exports.triageIncident = async (req, res) => {
  const result = await callAiJson(
    'You are a senior incident commander. Triage this incident with severity, priorityScore, summary, businessImpact, recommendedActions, containment, mitre, and evidenceNeeded.',
    req.body.incident || req.body,
    fallbackIncidentTriage
  );

  res.json({ success: true, ...result });
};

exports.generateReport = async (req, res) => {
  const result = await callAiJson(
    'You are a SOC reporting assistant. Generate an executive-ready JSON report with title, riskScore, confidence, summary, keyFindings, recommendedActions, and watchlist.',
    req.body,
    fallbackReport
  );

  res.json({ success: true, ...result });
};

exports.chat = async (req, res) => {
  const payload = {
    message: req.body.message || '',
    context: req.body.context || {}
  };

  const result = await callAiJson(
    'You are MicroSOC AI Assistant. Answer practical SOC questions briefly with clear next actions. Use JSON with answer and nextActions.',
    payload,
    safePayload => ({
      answer: fallbackChat(safePayload.message, safePayload.context),
      nextActions: ['Review high severity queue', 'Correlate logs around the event time', 'Document containment actions']
    })
  );

  res.json({ success: true, ...result });
};

exports.naturalSearch = async (req, res) => {
  const query = String(req.body.query || '');
  const lower = query.toLowerCase();
  const filters = {
    severity: ['critical', 'high', 'medium', 'low'].find(item => lower.includes(item)) || null,
    blocked: lower.includes('blocked') ? true : lower.includes('unblocked') || lower.includes('active') ? false : null,
    attackType: ['sql injection', 'xss', 'port scan', 'brute force', 'ddos', 'malware', 'phishing']
      .find(item => lower.includes(item)) || null,
    sourceIP: query.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || null,
    requestId: crypto.randomUUID()
  };

  res.json({
    success: true,
    mode: 'fallback',
    data: {
      query,
      filters,
      explanation: 'Use these parsed filters to narrow log results in the UI.'
    }
  });
};
