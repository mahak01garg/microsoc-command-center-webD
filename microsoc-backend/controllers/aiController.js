const crypto = require('crypto');
const Log = require('../models/Log');
const Incident = require('../models/Incident');
const SystemSettings = require('../models/SystemSettings');
const Alert = require('../models/Alert');
const AuditLog = require('../models/AuditLog');

const AI_PROVIDER = (process.env.AI_PROVIDER || (process.env.GEMINI_API_KEY ? 'gemini' : 'openai')).toLowerCase();
const DEFAULT_AI_BASE_URL = AI_PROVIDER === 'openrouter'
  ? 'https://openrouter.ai/api/v1'
  : 'https://api.openai.com/v1';
const AI_BASE_URL = (
  process.env.AI_BASE_URL
  || (AI_PROVIDER === 'openrouter' ? process.env.OPENROUTER_BASE_URL : '')
  || DEFAULT_AI_BASE_URL
).replace(/\/$/, '');
const IS_OPENROUTER = AI_PROVIDER === 'openrouter' || AI_BASE_URL.includes('openrouter.ai');
const AI_MODEL = process.env.AI_MODEL
  || (AI_PROVIDER === 'openrouter' ? process.env.OPENROUTER_MODEL : '')
  || (AI_PROVIDER === 'gemini' ? 'gemini-2.0-flash' : 'gpt-4o-mini');
const AI_API_KEY = process.env.AI_API_KEY || process.env.OPENAI_API_KEY || process.env.OPENROUTER_API_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_BASE_URL = (process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, '');
const AI_REQUIRE_PROVIDER = String(process.env.AI_REQUIRE_PROVIDER || 'true').toLowerCase() !== 'false';
const AI_ALLOW_LOCAL_FALLBACK = String(process.env.AI_ALLOW_LOCAL_FALLBACK || 'false').toLowerCase() === 'true';
const AI_TIMEOUT_MS = Number(process.env.AI_TIMEOUT_MS || 15000);
const AI_MAX_OUTPUT_TOKENS = Number(process.env.AI_MAX_OUTPUT_TOKENS || 450);
const AI_FORCE_RESPONSE_FORMAT = !IS_OPENROUTER
  && String(process.env.AI_FORCE_RESPONSE_FORMAT || 'true').toLowerCase() === 'true';
const AI_FALLBACK_MODELS = String(process.env.AI_FALLBACK_MODELS || '')
  .split(',')
  .map(model => model.trim())
  .filter(Boolean);

async function getAiSettings() {
  const settings = await SystemSettings.getSingleton();
  return {
    analysisEnabled: settings.aiSettings?.analysisEnabled !== false,
    autoGenerateRecommendations: settings.aiSettings?.autoGenerateRecommendations !== false
  };
}

function sendAiDisabled(res, message) {
  return res.status(403).json({
    success: false,
    mode: 'disabled',
    message
  });
}

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

function countBy(items = [], key = '_id') {
  return Object.fromEntries((Array.isArray(items) ? items : []).map(item => [item[key] || 'unknown', item.count || 0]));
}

async function buildProjectContext(req, clientContext = {}) {
  const activeLogQuery = { archived: { $ne: true } };
  const activeIncidentQuery = { archived: { $ne: true } };
  const activeAlertQuery = { deletedAt: { $exists: false } };

  const severityRankExpression = {
    $switch: {
      branches: [
        { case: { $eq: ['$severity', 'critical'] }, then: 4 },
        { case: { $eq: ['$severity', 'high'] }, then: 3 },
        { case: { $eq: ['$severity', 'medium'] }, then: 2 }
      ],
      default: 1
    }
  };

  const [
    settings,
    totalLogs,
    blockedLogs,
    logSeverity,
    logAttackTypes,
    topSources,
    countryMap,
    recentLogs,
    totalAlerts,
    alertSeverity,
    alertStatus,
    recentAlerts,
    totalIncidents,
    incidentStatus,
    incidentSeverity,
    openIncidents,
    auditTotal,
    recentAudit
  ] = await Promise.all([
    SystemSettings.getSingleton().catch(() => null),
    Log.countDocuments(activeLogQuery).catch(() => 0),
    Log.countDocuments({ ...activeLogQuery, isBlocked: true }).catch(() => 0),
    Log.aggregate([
      { $match: activeLogQuery },
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]).catch(() => []),
    Log.aggregate([
      { $match: activeLogQuery },
      { $group: { _id: '$attackType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]).catch(() => []),
    Log.aggregate([
      { $match: activeLogQuery },
      { $group: { _id: '$sourceIP', count: { $sum: 1 }, country: { $first: '$country' }, lastSeen: { $max: '$timestamp' } } },
      { $sort: { count: -1, lastSeen: -1 } },
      { $limit: 10 }
    ]).catch(() => []),
    Log.aggregate([
      { $match: { ...activeLogQuery, country: { $exists: true, $nin: [null, '', 'Unknown'] } } },
      {
        $group: {
          _id: '$country',
          count: { $sum: 1 },
          lastSeen: { $max: '$timestamp' },
          severityRank: { $max: severityRankExpression }
        }
      },
      { $sort: { count: -1, lastSeen: -1 } }
    ]).catch(() => []),
    Log.find(activeLogQuery)
      .sort({ timestamp: -1 })
      .limit(12)
      .select('timestamp attackType sourceIP targetSystem severity isBlocked country description')
      .lean()
      .catch(() => []),
    Alert.countDocuments(activeAlertQuery).catch(() => 0),
    Alert.aggregate([
      { $match: activeAlertQuery },
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]).catch(() => []),
    Alert.aggregate([
      { $match: activeAlertQuery },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]).catch(() => []),
    Alert.find(activeAlertQuery)
      .sort({ lastSeen: -1, createdAt: -1 })
      .limit(8)
      .select('title severity status sourceIP targetSystem attackType occurrenceCount firstSeen lastSeen')
      .lean()
      .catch(() => []),
    Incident.countDocuments(activeIncidentQuery).catch(() => 0),
    Incident.aggregate([
      { $match: activeIncidentQuery },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]).catch(() => []),
    Incident.aggregate([
      { $match: activeIncidentQuery },
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]).catch(() => []),
    Incident.find({ ...activeIncidentQuery, status: { $in: ['open', 'in_progress'] } })
      .sort({ updatedAt: -1, createdAt: -1 })
      .limit(8)
      .select('title severity status sourceIP priority updatedAt createdAt')
      .lean()
      .catch(() => []),
    AuditLog.countDocuments({}).catch(() => 0),
    AuditLog.find({})
      .sort({ timestamp: -1 })
      .limit(8)
      .select('timestamp actorName actorRole action module result details')
      .lean()
      .catch(() => [])
  ]);

  const settingsObject = settings?.toObject ? settings.toObject() : (settings || {});
  const blockedPct = totalLogs > 0 ? Math.round((blockedLogs / totalLogs) * 100) : 0;

  const requestUser = req.user?.toObject ? req.user.toObject() : (req.user || {});
  const safeUser = {
    id: String(requestUser._id || requestUser.id || clientContext.user?.id || ''),
    name: clientContext.user?.name || requestUser.name,
    email: clientContext.user?.email || requestUser.email,
    role: clientContext.user?.role || requestUser.role
  };

  return redactSensitive({
    product: {
      name: 'MicroSOC Command Center',
      purpose: 'SOC dashboard for security logs, alert correlation, incident management, analytics, audit logs, settings, users, notifications, and AI-assisted triage/reporting.',
      frontend: 'React shell loading legacy page modules from microsoc-frontend/src/pages.js and microsoc-frontend/js/*.js',
      backend: 'Express/Mongoose API with MongoDB, auth-protected routes, threshold-driven alert/incident automation, OpenRouter/OpenAI-compatible AI provider.',
      importantRules: [
        'Do not invent data. Use the projectSnapshot counts when answering operational questions.',
        'Alerts are generated only when thresholds are met: Brute Force uses failedLoginThreshold; other attack types use otherAlertsThreshold.',
        'Incidents are created only after alert occurrence count reaches createIncidentAfter.',
        'Attack map is all-time active logs grouped by normalized country aliases.',
        'AI local fallback is disabled unless AI_ALLOW_LOCAL_FALLBACK=true; user wants provider-generated answers.'
      ]
    },
    user: safeUser,
    clientContext,
    settings: {
      generalSettings: settingsObject.generalSettings,
      alertConfig: settingsObject.alertConfig,
      incidentConfig: settingsObject.incidentConfig,
      aiSettings: settingsObject.aiSettings,
      notificationSettings: settingsObject.notificationSettings
    },
    snapshot: {
      generatedAt: new Date().toISOString(),
      logs: {
        total: totalLogs,
        blocked: blockedLogs,
        blockedPct,
        severity: countBy(logSeverity),
        topAttackTypes: logAttackTypes.map(item => ({ attackType: item._id, count: item.count })),
        topSources: topSources.map(item => ({ sourceIP: item._id, count: item.count, country: item.country, lastSeen: item.lastSeen })),
        countryMap: countryMap.map(item => ({ country: item._id, count: item.count, severityRank: item.severityRank, lastSeen: item.lastSeen })),
        recent: recentLogs
      },
      alerts: {
        total: totalAlerts,
        severity: countBy(alertSeverity),
        status: countBy(alertStatus),
        recent: recentAlerts
      },
      incidents: {
        total: totalIncidents,
        status: countBy(incidentStatus),
        severity: countBy(incidentSeverity),
        openOrInProgress: openIncidents
      },
      auditLogs: {
        total: auditTotal,
        recent: recentAudit
      }
    }
  });
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

function getChatIntent(message = '') {
  const text = String(message || '').trim().toLowerCase();
  if (/^(hi|hello|hey|hii|hy|namaste|good morning|good afternoon|good evening)\b/i.test(text)) return 'greeting';
  if (/^(how are you|how r u|how's it going|are you ok|kaise ho|kese ho|kya haal)\b/i.test(text)) return 'wellbeing';
  if (text.includes('i asked') && text.includes('how are you')) return 'wellbeing';
  if (text.includes('who are you') || text.includes('what are you')) return 'assistant_identity';
  if (
    text.includes('do you know me')
    || text.includes('who am i')
    || text.includes('you know me')
    || text.includes('mera naam')
    || text.includes('my name')
  ) return 'user_identity';
  if (text.includes('what can you do') || text.includes('help me') || text === 'help') return 'capabilities';
  if (text.includes('thank')) return 'thanks';
  if (/^(bye|goodbye|see you|ok bye)\b/i.test(text)) return 'goodbye';
  return 'soc';
}

function isLocalChatIntent(message = '') {
  return getChatIntent(message) !== 'soc';
}

function fallbackChat(message = '', context = {}) {
  const normalized = String(message).toLowerCase();
  const recentAlerts = context.recentAlerts || [];
  const openIncidents = context.openIncidents || [];
  const user = context.user && typeof context.user === 'object' ? context.user : {};
  const userName = user.name || user.email || '';
  const userRole = user.role ? String(user.role).toUpperCase() : '';
  const intent = getChatIntent(message);
  if (intent === 'greeting') {
    return 'Hey! I am here and ready to help. What would you like to check in MicroSOC?';
  }
  if (intent === 'wellbeing') {
    return 'I am doing well and ready to help. Ask me anything about your MicroSOC alerts, incidents, logs, MITRE mapping, CVEs, or mitigation steps.';
  }
  if (intent === 'assistant_identity') {
    return 'I am MicroSOC AI, the built-in SOC assistant for this command center. I can help with alert triage, incident prioritization, MITRE/CVE context, and remediation planning.';
  }
  if (intent === 'user_identity') {
    if (userName) {
      return `Yes. In this session, I can see you as ${userName}${userRole ? ` with ${userRole} access` : ''}. I only know what the MicroSOC session provides, not anything outside this app.`;
    }
    return 'I can only know you from the current MicroSOC login session. Right now I cannot see a user name in the session context.';
  }
  if (intent === 'capabilities') {
    return 'I can summarize alerts, explain attacks, map MITRE techniques, identify related CVEs, suggest mitigations, prioritize incidents, and help interpret suspicious IPs or IOCs.';
  }
  if (intent === 'thanks') {
    return 'You are welcome. Send me any alert, incident, IOC, CVE, or attack type and I will help break it down clearly.';
  }
  if (intent === 'goodbye') {
    return 'Bye. I will be here when you want to investigate the next alert or incident.';
  }
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
  return 'I can help with MicroSOC alerts, incidents, logs, MITRE mapping, CVE context, IOC analysis, or mitigation steps. Ask me something like "summarize alerts", "explain this attack", or "what should I prioritize first?".';
}

function fallbackChatPayload(message = '', context = {}) {
  const answer = fallbackChat(message, context);
  const nextActions = isLocalChatIntent(message)
    ? []
    : [
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
  const candidates = [text];
  const match = text.match(/\{[\s\S]*\}/);
  if (match) candidates.push(match[0]);

  for (const candidate of candidates) {
    const parsed = tryParseJson(candidate);
    if (parsed) return parsed;

    const repaired = repairAiJson(candidate);
    const repairedParsed = tryParseJson(repaired);
    if (repairedParsed) return repairedParsed;
  }

  throw new Error('AI provider returned malformed JSON that could not be repaired.');
}

function tryParseJson(value) {
  try {
    return JSON.parse(value);
  } catch (error) {
    return null;
  }
}

function repairAiJson(value) {
  return String(value || '')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/,\s*([}\]])/g, '$1')
    .replace(/"\s*\n\s*"/g, '",\n"')
    .replace(/}\s*\n\s*"/g, '},\n"')
    .replace(/]\s*\n\s*"/g, '],\n"')
    .replace(/(\d)\s*\n\s*"/g, '$1,\n"');
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
    candidates.push('openai/gpt-4o-mini', 'openrouter/auto');
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
  if (body.error) {
    throw new Error(`AI provider error: ${JSON.stringify(body.error).slice(0, 240)}`);
  }
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
    const settings = await getAiSettings();
    if (!settings.analysisEnabled) {
      return sendAiDisabled(res, 'AI analysis is disabled in SOC settings.');
    }
    if (!settings.autoGenerateRecommendations) {
      return sendAiDisabled(res, 'AI report generation is disabled by Auto Generate Recommendations setting.');
    }

    const result = await callAiJson(
      [
        'You are a SOC reporting assistant.',
        'Return one valid JSON object only with exactly these keys: title, riskScore, confidence, summary, keyFindings, recommendedActions, watchlist.',
        'keyFindings, recommendedActions, and watchlist must be arrays of short strings. Do not use nested objects inside arrays.',
        'The user may send summarized telemetry instead of raw logs. Use the provided counts, top attack types, top sources, critical samples, anomalies, predictions, and remediations.',
        'Do not say that raw logs are missing if summarized telemetry is available. Do not add trailing commas.'
      ].join(' '),
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

  const settings = await getAiSettings();
  if (!settings.analysisEnabled) {
    return sendAiDisabled(res, 'AI analysis is disabled in SOC settings.');
  }

  const projectContext = await buildProjectContext(req, req.body.context || {});
  const payload = {
    message,
    context: projectContext
  };

  try {
    const result = await callAiJson(
      [
        'You are MicroSOC AI, the built-in SOC assistant for MicroSOC Command Center.',
        'Identity rule: if asked who you are, say you are MicroSOC AI. Never claim to be an animal, owl, generic chatbot, or unrelated persona.',
        'Respond naturally. If the user asks casual small-talk, answer casually without forcing SOC triage.',
        'You have project-wide MicroSOC context in context.product, context.settings, and context.snapshot. Treat that as the source of truth for this app and its current data.',
        'For security operations questions, give practical next actions. You can explain logs, alerts, incidents, audit activity, dashboard metrics, thresholds, settings, attack map, top attackers, AI configuration, notifications, and remediation.',
        'When asked about current counts or status, use context.snapshot exactly. If a value is absent, say it is not available instead of guessing.',
        'When asked how MicroSOC works, use context.product and context.settings. Mention threshold logic accurately.',
        'If asked about the logged-in user, use context.user when available and do not invent personal details.',
        'Use JSON with answer and nextActions. Keep answer under 120 words unless the user asks for detail.'
      ].join(' '),
      payload
    );

    result.data = normalizeChatData(result.data);
    res.json({ success: true, ...result });
  } catch (error) {
    if (AI_ALLOW_LOCAL_FALLBACK) {
      const fallbackAnswer = fallbackChat(message, payload.context);
      const fallback = normalizeChatData(
        { answer: fallbackAnswer },
        { answer: fallbackAnswer, nextActions: [] }
      );
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
    const settings = await getAiSettings();
    if (!settings.analysisEnabled) {
      return sendAiDisabled(res, 'AI analysis is disabled in SOC settings.');
    }

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
