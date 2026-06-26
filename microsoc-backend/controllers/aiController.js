const crypto = require('crypto');
const Log = require('../models/Log');
const Incident = require('../models/Incident');

const AI_PROVIDER = (process.env.AI_PROVIDER || (process.env.GEMINI_API_KEY ? 'gemini' : 'openai')).toLowerCase();
const AI_BASE_URL = (process.env.AI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, '');
const IS_OPENROUTER = AI_BASE_URL.includes('openrouter.ai');
const AI_MODEL = process.env.AI_MODEL || (AI_PROVIDER === 'gemini' ? 'gemini-2.0-flash' : 'gpt-4o-mini');
const AI_API_KEY = process.env.AI_API_KEY || process.env.OPENAI_API_KEY || process.env.OPENROUTER_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_BASE_URL = (process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, '');
const AI_REQUIRE_PROVIDER = true;
const AI_ALLOW_LOCAL_FALLBACK = String(process.env.AI_ALLOW_LOCAL_FALLBACK || 'true').toLowerCase() === 'true';
const AI_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 15000);
const AI_MAX_OUTPUT_TOKENS = Number(process.env.AI_MAX_OUTPUT_TOKENS || 450);
const AI_FORCE_RESPONSE_FORMAT = String(process.env.AI_FORCE_RESPONSE_FORMAT || (!IS_OPENROUTER)).toLowerCase() === 'true';
const AI_FALLBACK_MODELS = String(process.env.AI_FALLBACK_MODELS || '')
  .split(',')
  .map(model => model.trim())
  .filter(Boolean);

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
  const recentAlerts = context.recentAlerts || [];
  const openIncidents = context.openIncidents || [];
  if (normalized.includes('summarize') && (normalized.includes('alert') || normalized.includes('log'))) {
    const criticalHigh = recentAlerts.filter(alert => ['critical', 'high'].includes(alert.severity)).length;
    const topTypes = [...new Set(recentAlerts.map(alert => alert.attackType).filter(Boolean))].slice(0, 4);
    return `Last ${recentAlerts.length} alerts include ${criticalHigh} critical/high events. Main attack families: ${topTypes.join(', ') || 'not enough data'}. Prioritize unblocked critical/high alerts and repeated source IPs.`;
  }
  if (normalized.includes('explain') && normalized.includes('attack')) {
    const latest = recentAlerts[0] || {};
    return `${latest.attackType || 'This attack'} appears to target ${latest.targetSystem || 'an exposed system'} from ${latest.sourceIP || 'an unknown source'}. Severity is ${latest.severity || 'medium'}; verify impact, collect raw payloads, and contain repeated sources.`;
  }
  if (normalized.includes('mitigation') || normalized.includes('mitigate') || normalized.includes('steps')) {
    const latest = recentAlerts[0] || {};
    return `Suggested mitigation: block or challenge ${latest.sourceIP || 'the noisy source'}, confirm whether ${latest.targetSystem || 'the target'} was affected, tune WAF/IDS rules for ${latest.attackType || 'the attack family'}, and document containment in the incident timeline.`;
  }
  if (normalized.includes('severity')) {
    const unresolvedCritical = openIncidents.filter(incident => incident.severity === 'critical').length;
    return `Severity should be driven by exploitability, affected asset criticality, blocked/unblocked status, and repeated activity. Current context shows ${unresolvedCritical} open critical incident(s).`;
  }
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

function fallbackChatPayload(message = '', context = {}) {
  const answer = fallbackChat(message, context);
  const nextActions = [
    'Review the latest critical/high alerts',
    'Inspect related logs and incident timelines',
    'Apply temporary containment if the source is repeated'
  ];

  return normalizeChatData({ answer, nextActions }, { answer, nextActions });
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function callAiJson(systemPrompt, userPayload) {
  const safePayload = redactSensitive(userPayload);
  const hasProviderKey = AI_PROVIDER === 'gemini' ? GEMINI_API_KEY : AI_API_KEY;

  if (!hasProviderKey) {
    throw new Error(`${AI_PROVIDER} API key is not configured`);
  }

  try {
    const content = AI_PROVIDER === 'gemini'
      ? await callGeminiJson(systemPrompt, safePayload)
      : await callOpenAiJsonWithFallback(systemPrompt, safePayload);

    if (!content) throw new Error('AI provider returned empty content');

    return { mode: 'ai', data: parseAiJson(content) };
  } catch (error) {
    console.error('AI provider failed:', error.message);
    throw error;
  }
}

function parseAiJson(content) {
  const text = String(content || '')
    .trim()
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/, '')
    .trim();
  try {
    return JSON.parse(text);
  } catch (error) {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) throw error;
    return JSON.parse(match[0]);
  }
}

function normalizeStringArray(value) {
  if (Array.isArray(value)) {
    return value
      .flatMap(item => normalizeStringArray(item))
      .filter(Boolean);
  }
  if (value && typeof value === 'object') {
    return Object.values(value)
      .flatMap(item => normalizeStringArray(item))
      .filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(/\n|(?:^|\s)\d+\.\s+|[;•]/)
      .map(item => item.replace(/^[-*]\s*/, '').trim())
      .filter(Boolean);
  }
  if (value === null || value === undefined) return [];
  return [String(value)];
}

function normalizeAiAnalysis(data = {}, fallbackData = {}) {
  const merged = { ...fallbackData, ...(data && typeof data === 'object' ? data : {}) };
  return {
    ...merged,
    risk: Number.isFinite(Number(merged.risk)) ? Math.max(0, Math.min(100, Number(merged.risk))) : fallbackData.risk,
    priorityScore: Number.isFinite(Number(merged.priorityScore))
      ? Math.max(0, Math.min(100, Number(merged.priorityScore)))
      : fallbackData.priorityScore,
    recommendedActions: normalizeStringArray(merged.recommendedActions || merged.actions || fallbackData.recommendedActions),
    containment: normalizeStringArray(merged.containment || fallbackData.containment),
    mitre: normalizeStringArray(merged.mitre || merged.mitreMapping || fallbackData.mitre),
    evidenceNeeded: normalizeStringArray(merged.evidenceNeeded || merged.evidence || fallbackData.evidenceNeeded)
  };
}

function normalizeReportData(data = {}, fallbackData = {}) {
  const merged = { ...fallbackData, ...(data && typeof data === 'object' ? data : {}) };
  return {
    ...merged,
    riskScore: Number.isFinite(Number(merged.riskScore)) ? Math.max(0, Math.min(100, Number(merged.riskScore))) : fallbackData.riskScore,
    confidence: Number.isFinite(Number(merged.confidence)) ? Math.max(0, Math.min(100, Number(merged.confidence))) : fallbackData.confidence,
    keyFindings: normalizeStringArray(merged.keyFindings || fallbackData.keyFindings),
    recommendedActions: normalizeStringArray(merged.recommendedActions || merged.actions || fallbackData.recommendedActions),
    watchlist: normalizeStringArray(merged.watchlist || fallbackData.watchlist)
  };
}

function normalizeChatData(data = {}, fallbackData = {}) {
  const merged = { ...fallbackData, ...(data && typeof data === 'object' ? data : {}) };
  return {
    ...merged,
    answer: String(merged.answer || fallbackData.answer || ''),
    nextActions: normalizeStringArray(merged.nextActions || merged.recommendedActions || fallbackData.nextActions)
  };
}

function getOpenAiModelCandidates() {
  const candidates = [AI_MODEL, ...AI_FALLBACK_MODELS];
  if (IS_OPENROUTER) {
    candidates.push('openrouter/auto', 'openai/gpt-4o-mini');
  } else {
    candidates.push('gpt-4o-mini');
  }
  return [...new Set(candidates.filter(Boolean))];
}

function isLikelyModelError(errorBody = '') {
  const text = String(errorBody).toLowerCase();
  return [
    'model',
    'invalid',
    'not found',
    'unsupported',
    'does not exist',
    'not available'
  ].some(fragment => text.includes(fragment));
}

async function callOpenAiJson(systemPrompt, safePayload, model = AI_MODEL) {
  const requestBody = {
    model,
    temperature: 0.2,
    max_tokens: AI_MAX_OUTPUT_TOKENS,
    messages: [
      { role: 'system', content: `${systemPrompt}\nReturn only valid JSON. Do not wrap the JSON in Markdown.` },
      { role: 'user', content: JSON.stringify(safePayload) }
    ]
  };

  if (AI_FORCE_RESPONSE_FORMAT) {
    requestBody.response_format = { type: 'json_object' };
  }

  const response = await fetchWithTimeout(`${AI_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${AI_API_KEY}`,
      'Content-Type': 'application/json',
      ...(IS_OPENROUTER ? {
        'HTTP-Referer': process.env.FRONTEND_URL || 'http://localhost:5173',
        'X-OpenRouter-Title': 'MicroSOC Command Center'
      } : {})
    },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(`AI provider returned ${response.status}: ${errorBody.slice(0, 240)}`);
  }

  const body = await response.json();
  const content = body.choices?.[0]?.message?.content;
  if (Array.isArray(content)) {
    return content.map(part => part.text || part.content || '').join('');
  }
  return content;
}

async function callOpenAiJsonWithFallback(systemPrompt, safePayload) {
  const candidates = getOpenAiModelCandidates();
  let lastError = null;

  for (const model of candidates) {
    try {
      const content = await callOpenAiJson(systemPrompt, safePayload, model);
      if (content) {
        return content;
      }
      lastError = new Error(`AI provider returned empty content for model ${model}`);
    } catch (error) {
      lastError = error;
      if (!isLikelyModelError(error.message)) {
        throw error;
      }
    }
  }

  throw lastError || new Error('AI provider returned no usable content');
}

async function callGeminiJson(systemPrompt, safePayload) {
  const model = encodeURIComponent(AI_MODEL);
  const url = `${GEMINI_BASE_URL}/models/${model}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
  const prompt = [
    systemPrompt,
    'Return only valid JSON. Do not wrap the JSON in Markdown.',
    JSON.stringify(safePayload)
  ].join('\n\n');

  const response = await fetchWithTimeout(url, {
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
        maxOutputTokens: AI_MAX_OUTPUT_TOKENS,
        responseMimeType: 'application/json'
      }
    })
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(`Gemini provider returned ${response.status}: ${errorBody.slice(0, 240)}`);
  }

  const body = await response.json();
  return body.candidates?.[0]?.content?.parts
    ?.map(part => part.text || '')
    .join('')
    .trim();
}

exports.explainLog = async (req, res) => {
  try {
    const input = req.body.log || req.body;
    const result = await callAiJson(
      'You are a senior SOC analyst. Explain a security log with concise risk, likely intent, MITRE mapping, containment, and evidence needed.',
      input
    );

    result.data = normalizeAiAnalysis(result.data);
    res.json({ success: true, ...result });
  } catch (error) {
    if (AI_ALLOW_LOCAL_FALLBACK) {
      const input = req.body.log || req.body;
      const fallback = normalizeAiAnalysis(fallbackLogExplanation(input));
      console.warn('AI explain-log provider failed, using fallback:', error.message);
      res.json({
        success: true,
        mode: 'fallback',
        data: fallback,
        providerError: error.message
      });
      return;
    }
    res.status(502).json({
      success: false,
      mode: 'ai_error',
      message: 'AI provider rejected the request',
      detail: error.message
    });
  }
};

exports.status = async (req, res) => {
  const baseUrl = AI_PROVIDER === 'gemini' ? GEMINI_BASE_URL : AI_BASE_URL;
  const hasProviderKey = AI_PROVIDER === 'gemini' ? Boolean(GEMINI_API_KEY) : Boolean(AI_API_KEY);

  res.json({
    success: true,
    provider: AI_PROVIDER,
    model: AI_MODEL,
    fallbackModels: AI_FALLBACK_MODELS,
    baseUrl,
    hasProviderKey,
    requireProvider: AI_REQUIRE_PROVIDER,
    timeoutMs: AI_TIMEOUT_MS,
    maxOutputTokens: AI_MAX_OUTPUT_TOKENS,
    openRouter: IS_OPENROUTER,
    healthy: Boolean(hasProviderKey)
  });
};

exports.triageIncident = async (req, res) => {
  try {
    const input = req.body.incident || req.body;
    const result = await callAiJson(
      'You are a senior incident commander. Triage this incident with severity, priorityScore, summary, businessImpact, recommendedActions, containment, mitre, and evidenceNeeded.',
      input
    );

    result.data = normalizeAiAnalysis(result.data);
    res.json({ success: true, ...result });
  } catch (error) {
    if (AI_ALLOW_LOCAL_FALLBACK) {
      const input = req.body.incident || req.body;
      const fallback = normalizeAiAnalysis(fallbackIncidentTriage(input));
      console.warn('AI triage provider failed, using fallback:', error.message);
      res.json({
        success: true,
        mode: 'fallback',
        data: fallback,
        providerError: error.message
      });
      return;
    }
    res.status(502).json({
      success: false,
      mode: 'ai_error',
      message: 'AI provider rejected the request',
      detail: error.message
    });
  }
};

exports.generateReport = async (req, res) => {
  try {
    const result = await callAiJson(
      'You are a SOC reporting assistant. Generate an executive-ready JSON report with title, riskScore, confidence, summary, keyFindings, recommendedActions, and watchlist.',
      req.body
    );

    result.data = normalizeReportData(result.data);
    res.json({ success: true, ...result });
  } catch (error) {
    if (AI_ALLOW_LOCAL_FALLBACK) {
      const fallback = normalizeReportData(fallbackReport(req.body));
      console.warn('AI report provider failed, using fallback:', error.message);
      res.json({
        success: true,
        mode: 'fallback',
        data: fallback,
        providerError: error.message
      });
      return;
    }
    res.status(502).json({
      success: false,
      mode: 'ai_error',
      message: 'AI provider rejected the request',
      detail: error.message
    });
  }
};

exports.chat = async (req, res) => {
  const message = req.body.message || '';
  const recentAlerts = await Log.find()
    .sort({ timestamp: -1 })
    .limit(20)
    .select('timestamp attackType sourceIP targetSystem severity isBlocked country description')
    .lean()
    .catch(() => []);
  const openIncidents = await Incident.find({ status: { $in: ['open', 'in_progress'] } })
    .sort({ createdAt: -1 })
    .limit(10)
    .select('title severity status sourceIP priority')
    .lean()
    .catch(() => []);
  const payload = {
    message,
    context: {
      ...(req.body.context || {}),
      recentAlerts,
      openIncidents
    }
  };

  try {
    const result = await callAiJson(
      [
        'You are MicroSOC AI, the built-in SOC assistant for MicroSOC Command Center.',
        'Identity rule: if asked who you are, say you are MicroSOC AI. Never claim to be an animal, owl, generic chatbot, or unrelated persona.',
        'Scope: answer practical security operations questions with concise next actions. You can explain attacks, summarize recent alerts, suggest mitigations, assess severity, and reference MITRE-style techniques.',
        'Use JSON with answer and nextActions. Keep answer under 120 words unless the user asks for detail.'
      ].join(' '),
      payload
    );

    result.data = normalizeChatData(result.data);
    res.json({ success: true, ...result });
  } catch (error) {
    if (AI_ALLOW_LOCAL_FALLBACK) {
      const fallback = fallbackChatPayload(message, payload.context);
      console.warn('AI chat provider failed, using fallback:', error.message);
      res.json({
        success: true,
        mode: 'fallback',
        data: fallback,
        providerError: error.message
      });
      return;
    }
    res.status(502).json({
      success: false,
      mode: 'ai_error',
      message: 'AI provider rejected the request',
      detail: error.message
    });
  }
};

exports.naturalSearch = async (req, res) => {
  const query = String(req.body.query || '');

  try {
    const result = await callAiJson(
      [
        'You convert SOC log search text into JSON filters.',
        'Return JSON with query, filters, and explanation.',
        'filters may include severity, blocked, attackType, sourceIP, and requestId.',
        'Use null for unknown filters and keep explanation under 25 words.'
      ].join(' '),
      {
        query,
        allowedSeverities: ['critical', 'high', 'medium', 'low'],
        allowedAttackTypes: ['sql injection', 'xss', 'port scan', 'brute force', 'ddos', 'malware', 'phishing'],
        requestId: crypto.randomUUID()
      }
    );

    res.json({ success: true, ...result });
  } catch (error) {
    if (AI_ALLOW_LOCAL_FALLBACK) {
      const queryText = query.toLowerCase();
      const fallback = {
        query,
        explanation: 'Used local MicroSOC fallback because the AI provider rejected the request.',
        filters: {
          severity: queryText.includes('critical') ? 'critical' : queryText.includes('high') ? 'high' : null,
          blocked: queryText.includes('blocked') ? true : null,
          attackType: queryText.includes('sql') ? 'SQL Injection' : queryText.includes('xss') ? 'XSS' : null,
          sourceIP: /\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(query) ? query.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)?.[0] : null,
          requestId: crypto.randomUUID()
        }
      };
      console.warn('AI natural-search provider failed, using fallback:', error.message);
      res.json({
        success: true,
        mode: 'fallback',
        data: fallback,
        providerError: error.message
      });
      return;
    }
    res.status(502).json({
      success: false,
      mode: 'ai_error',
      message: 'AI provider rejected the request',
      detail: error.message
    });
  }
};
