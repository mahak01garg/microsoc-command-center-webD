const Log = require('../models/Log');
const Incident = require('../models/Incident');
const Alert = require('../models/Alert');
const SystemSettings = require('../models/SystemSettings');
const realtimeHub = require('./realtimeHub');
const jobQueue = require('./jobQueue');

const JOB_RETRY_LIMIT = 3;
const JOB_BASE_BACKOFF_MS = 250;
const AUTO_INCIDENT_TAG = 'auto-generated';
const AUTO_SOURCE_TAG = 'auto-threat-pipeline';
const ATTACK_TYPE_ALIASES = {
  'sql injection': 'SQL Injection',
  'xss': 'XSS',
  'port scan': 'Port Scan',
  'brute force': 'Brute Force',
  'ddos': 'DDoS',
  'malware': 'Malware',
  'phishing': 'Phishing',
  'insider threat': 'Insider Threat',
  'ransomware': 'Ransomware',
  'zero-day': 'Zero-Day',
  'mitm': 'MITM',
  'credential theft': 'Credential Theft',
  'credential stuffing': 'Credential Stuffing',
  'password spraying': 'Password Spraying',
  'password spray': 'Password Spraying',
  'data exfiltration': 'Data Exfiltration',
  'powershell abuse': 'PowerShell Abuse',
  'powershell': 'PowerShell Abuse',
  'iot attack': 'IoT Attack',
  'supply chain': 'Supply Chain',
  'microsoft outlook exploit': 'Microsoft Outlook Exploit',
  'apache struts exploit': 'Apache Struts Exploit',
  'exchange server exploit': 'Exchange Server Exploit',
  'log4shell exploit': 'Log4Shell Exploit',
  'other': 'Other'
};

const SQLI_PATTERN = /(\bunion\b.*\bselect\b|\bor\b\s+\d+\s*=\s*\d+|drop\s+table|--|\/\*|\bselect\b.+\bfrom\b)/i;
const XSS_PATTERN = /<script|onerror\s*=|onload\s*=|javascript:/i;
const FAILED_LOGIN_PATTERN = /failed login|invalid password|authentication failed|login failed/i;
const DEFAULT_PIPELINE_SETTINGS = {
  alertConfig: {
    failedLoginThreshold: 5,
    otherAlertsThreshold: 1
  },
  incidentConfig: {
    createIncidentAfter: 3,
    severityEscalationEnabled: true
  }
};

let jobCounter = 0;
let processorRegistered = false;

function generateJobId() {
  jobCounter += 1;
  return `job_${Date.now()}_${jobCounter}`;
}

function sanitizeString(value) {
  return String(value ?? '')
    .replace(/[<>]/g, '')
    .replace(/\u0000/g, '')
    .trim();
}

function isValidIp(value) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)$/.test(String(value || '').trim());
}

function relatedCvesForAttack(value = '') {
  const key = String(value || '').toLowerCase();
  if (key.includes('microsoft outlook exploit') || key.includes('outlook exploit')) return ['CVE-2023-23397'];
  if (key.includes('apache struts exploit') || key.includes('struts exploit')) return ['CVE-2017-5638'];
  if (key.includes('exchange server exploit') || key.includes('exchange exploit') || key.includes('proxylogon') || key.includes('proxyshell')) return ['CVE-2021-26855', 'CVE-2021-34473'];
  if (key.includes('log4shell exploit') || key.includes('log4j exploit') || key.includes('log4shell')) return ['CVE-2021-44228'];
  return [];
}

function normalizeLogInput(payload) {
  const attackType = sanitizeString(payload.attackType);
  const normalizedAttackType = ATTACK_TYPE_ALIASES[attackType.toLowerCase()] || attackType;

  return {
    ...payload,
    attackType: normalizedAttackType,
    sourceIP: sanitizeString(payload.sourceIP),
    targetSystem: sanitizeString(payload.targetSystem),
    country: sanitizeString(payload.country || 'Unknown') || 'Unknown',
    description: sanitizeString(payload.description),
    userAgent: sanitizeString(payload.userAgent || 'Unknown') || 'Unknown',
    protocol: sanitizeString(payload.protocol || 'Other') || 'Other',
    severity: sanitizeString(payload.severity || 'medium').toLowerCase(),
    port: payload.port === '' || payload.port === null || payload.port === undefined
      ? undefined
      : Number(payload.port),
    isBlocked: Boolean(payload.isBlocked),
    metadata: payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : undefined,
    tags: Array.isArray(payload.tags) ? payload.tags.map(tag => sanitizeString(tag)).filter(Boolean) : undefined
  };
}

function validateLogPayload(payload) {
  const normalized = normalizeLogInput(payload);
  const allowedSeverities = new Set(['critical', 'high', 'medium', 'low', 'info']);

  if (!normalized.attackType) {
    throw new Error('Attack type is required');
  }
  if (!Object.values(ATTACK_TYPE_ALIASES).includes(normalized.attackType)) {
    throw new Error(`Unsupported attack type: ${normalized.attackType}`);
  }
  if (!isValidIp(normalized.sourceIP)) {
    throw new Error('A valid source IP is required');
  }
  if (!normalized.targetSystem) {
    throw new Error('Target system is required');
  }
  if (!normalized.description) {
    throw new Error('Description is required');
  }
  if (!allowedSeverities.has(normalized.severity)) {
    normalized.severity = 'medium';
  }

  return normalized;
}

function makeAlert(rule, log, extras = {}) {
  const severity = extras.severity || rule.severity || log.severity || 'medium';
  return {
    title: extras.title || `${rule.name} detected`,
    message: extras.message || `${log.attackType} activity from ${log.sourceIP} matched ${rule.name}.`,
    severity,
    ruleId: rule.id,
    mitreTechnique: rule.mitreTechnique,
    timestamp: new Date().toISOString(),
    sourceIP: log.sourceIP,
    targetSystem: log.targetSystem,
    attackType: log.attackType,
    evidence: extras.evidence || {},
    recommendedAction: extras.recommendedAction || rule.recommendedAction
  };
}

function alertCorrelationKey(log, ruleId) {
  return `${AUTO_SOURCE_TAG}:${ruleId}:${log.sourceIP}:${log.targetSystem}`;
}

async function persistAlert(log, detection, incidentResult) {
  const now = new Date();
  const correlationKey = alertCorrelationKey(log, detection.id);
  const update = {
    title: detection.alert.title,
    description: detection.alert.message,
    severity: detection.alert.severity,
    status: 'new',
    sourceIP: log.sourceIP,
    targetSystem: log.targetSystem,
    attackType: log.attackType,
    mitreTechnique: detection.mitreTechnique,
    ruleId: detection.id,
    correlationKey,
    evidence: detection.alert.evidence,
    metadata: {
      recommendedAction: detection.recommendedAction,
      logId: log._id,
      incidentId: incidentResult?.incident?._id || incidentResult?.incident?.id || null,
      source: 'threat-pipeline'
    },
    log: log._id,
    incident: incidentResult?.incident?._id || incidentResult?.incident?.id || undefined,
    occurrenceCount: 1,
    firstSeen: now,
    lastSeen: now,
    tags: [AUTO_INCIDENT_TAG, detection.id, log.attackType]
  };

  const alert = await Alert.findOne({ correlationKey, deletedAt: { $exists: false } });

  if (!alert) {
    return Alert.create(update);
  }

  alert.title = update.title;
  alert.description = update.description;
  alert.severity = update.severity;
  alert.status = update.status;
  alert.sourceIP = update.sourceIP;
  alert.targetSystem = update.targetSystem;
  alert.attackType = update.attackType;
  alert.mitreTechnique = update.mitreTechnique;
  alert.ruleId = update.ruleId;
  alert.evidence = update.evidence;
  alert.metadata = { ...(alert.metadata || {}), ...update.metadata };
  alert.log = update.log;
  if (update.incident) alert.incident = update.incident;
  alert.occurrenceCount = (alert.occurrenceCount || 0) + 1;
  alert.lastSeen = now;
  alert.tags = Array.from(new Set([...(alert.tags || []), ...update.tags]));

  return alert.save();
}

function incidentTitleForAlert(alert) {
  return `Auto Incident: ${alert.title}`;
}

function incidentCategoryForAlert(alert) {
  if (alert.ruleId === 'sql_injection' || alert.ruleId === 'xss_attack') return 'vulnerability';
  if (alert.ruleId === 'brute_force') return 'vulnerability';
  if (alert.ruleId === 'malware_detected' || alert.ruleId === 'ransomware_detected') return 'malware';
  if (alert.ruleId === 'phishing_detected') return 'phishing';
  if (alert.ruleId === 'data_exfiltration') return 'data_breach';
  if (alert.ruleId === 'port_scan' || alert.ruleId === 'anomaly_spike') return 'other';
  if (alert.ruleId === 'multi_stage_attack') return 'insider_threat';
  return 'other';
}

async function getRecentLogsForSource(sourceIP, minutes) {
  const startDate = new Date(Date.now() - minutes * 60 * 1000);
  return Log.find({ sourceIP, timestamp: { $gte: startDate } })
    .sort({ timestamp: -1 })
    .lean();
}

function normalizePipelineSettings(settings) {
  const source = settings?.toObject ? settings.toObject() : (settings || {});
  return {
    alertConfig: {
      ...DEFAULT_PIPELINE_SETTINGS.alertConfig,
      ...(source.alertConfig || {})
    },
    incidentConfig: {
      ...DEFAULT_PIPELINE_SETTINGS.incidentConfig,
      ...(source.incidentConfig || {})
    }
  };
}

async function getPipelineSettings() {
  try {
    const settings = await SystemSettings.getSingleton();
    return normalizePipelineSettings(settings);
  } catch (error) {
    console.warn('Threat pipeline settings fallback:', error.message);
    return normalizePipelineSettings(DEFAULT_PIPELINE_SETTINGS);
  }
}

function otherAttackRule(attackType) {
  const rules = {
    'SQL Injection': {
      severity: 'critical',
      mitreTechnique: 'T1190',
      confidence: 97,
      riskScore: 96,
      recommendedAction: 'Block the source IP, inspect the vulnerable endpoint, and review database error logs.'
    },
    XSS: {
      name: 'XSS Attack',
      severity: 'critical',
      mitreTechnique: 'T1190',
      confidence: 96,
      riskScore: 95,
      recommendedAction: 'Sanitize inputs, review the affected route, and enforce strict output encoding.'
    },
    'Microsoft Outlook Exploit': {
      severity: 'critical',
      mitreTechnique: 'T1203',
      confidence: 94,
      riskScore: 92,
      recommendedAction: 'Patch Outlook clients, monitor NTLM activity, and review suspicious calendar invites.'
    },
    'Apache Struts Exploit': {
      severity: 'critical',
      mitreTechnique: 'T1190',
      confidence: 95,
      riskScore: 94,
      recommendedAction: 'Patch Apache Struts, block exploit headers, and review web server command execution.'
    },
    'Exchange Server Exploit': {
      severity: 'critical',
      mitreTechnique: 'T1190',
      confidence: 95,
      riskScore: 95,
      recommendedAction: 'Patch Exchange Server, hunt for web shells, and review IIS/Exchange logs.'
    },
    'Log4Shell Exploit': {
      severity: 'critical',
      mitreTechnique: 'T1190',
      confidence: 97,
      riskScore: 97,
      recommendedAction: 'Patch Log4j, block JNDI exploit strings, and hunt for outbound LDAP/RMI callbacks.'
    },
    'Port Scan': {
      severity: 'medium',
      mitreTechnique: 'T1046',
      confidence: 88,
      riskScore: 55,
      recommendedAction: 'Block the scanner source IP and review exposed services.'
    },
    DDoS: {
      name: 'DDoS / Traffic Spike',
      severity: 'high',
      mitreTechnique: 'T1498',
      confidence: 86,
      riskScore: 82,
      recommendedAction: 'Rate-limit noisy origins, validate service health, and review upstream protection.'
    },
    Malware: {
      severity: 'critical',
      mitreTechnique: 'T1204',
      confidence: 94,
      riskScore: 91,
      recommendedAction: 'Isolate the host, collect malware indicators, and run endpoint containment.'
    },
    Phishing: {
      severity: 'high',
      mitreTechnique: 'T1566',
      confidence: 90,
      riskScore: 80,
      recommendedAction: 'Quarantine the message/source, review clicked users, and reset exposed credentials.'
    },
    Ransomware: {
      severity: 'critical',
      mitreTechnique: 'T1486',
      confidence: 96,
      riskScore: 98,
      recommendedAction: 'Disconnect affected systems, preserve evidence, and begin ransomware containment.'
    },
    'Credential Theft': {
      severity: 'high',
      mitreTechnique: 'T1003',
      confidence: 90,
      riskScore: 86,
      recommendedAction: 'Invalidate sessions, rotate credentials, and review identity provider logs.'
    },
    'Credential Stuffing': {
      severity: 'high',
      mitreTechnique: 'T1110',
      confidence: 90,
      riskScore: 84,
      recommendedAction: 'Rate-limit authentication, enforce MFA, and block repeated credential attempts.'
    },
    'Password Spraying': {
      severity: 'high',
      mitreTechnique: 'T1110.003',
      confidence: 90,
      riskScore: 84,
      recommendedAction: 'Lock suspicious sources, enforce MFA, and review account lockout telemetry.'
    },
    'PowerShell Abuse': {
      severity: 'high',
      mitreTechnique: 'T1059.001',
      confidence: 88,
      riskScore: 82,
      recommendedAction: 'Constrain PowerShell, collect script block logs, and isolate affected hosts.'
    },
    'Data Exfiltration': {
      severity: 'high',
      mitreTechnique: 'T1030',
      confidence: 90,
      riskScore: 82,
      recommendedAction: 'Pause outbound transfers, isolate the system, and validate data-loss boundaries.'
    }
  };
  const base = rules[attackType] || {
    severity: 'medium',
    mitreTechnique: 'T1040',
    confidence: 82,
    riskScore: 60,
    recommendedAction: 'Review the related logs, validate impact, and contain repeated suspicious sources.'
  };

  return {
    id: `${attackType.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'other'}_alert`,
    name: base.name || attackType,
    ...base
  };
}

async function detectThreats(log, settings = DEFAULT_PIPELINE_SETTINGS) {
  const alertConfig = {
    ...DEFAULT_PIPELINE_SETTINGS.alertConfig,
    ...(settings.alertConfig || {})
  };
  const failedLoginThreshold = Math.max(1, Number(alertConfig.failedLoginThreshold) || DEFAULT_PIPELINE_SETTINGS.alertConfig.failedLoginThreshold);
  const otherAlertsThreshold = Math.max(1, Number(alertConfig.otherAlertsThreshold) || DEFAULT_PIPELINE_SETTINGS.alertConfig.otherAlertsThreshold);

  const recent5m = await getRecentLogsForSource(log.sourceIP, 5);
  const recent10m = await getRecentLogsForSource(log.sourceIP, 10);

  const detections = [];
  const currentText = `${log.attackType} ${log.description} ${log.userAgent || ''}`;
  const effectiveAttackType = SQLI_PATTERN.test(currentText)
    ? 'SQL Injection'
    : XSS_PATTERN.test(currentText)
      ? 'XSS'
      : log.attackType;

  const failedLoginCount = recent5m.filter(item => {
    const text = `${item.attackType} ${item.description || ''} ${item.userAgent || ''}`;
    return item.attackType === 'Brute Force' || FAILED_LOGIN_PATTERN.test(text);
  }).length;

  if (failedLoginCount >= failedLoginThreshold) {
    detections.push({
      id: 'brute_force',
      name: 'Brute Force',
      severity: 'high',
      mitreTechnique: 'T1110',
      confidence: 92,
      windowMinutes: 5,
      riskScore: 78,
      recommendedAction: 'Lock the source IP, review authentication logs, and force credential reset for impacted users.',
      alert: makeAlert(
        {
          id: 'brute_force',
          name: 'Brute Force',
          severity: 'high',
          mitreTechnique: 'T1110',
          recommendedAction: 'Lock the source IP, review authentication logs, and force credential reset for impacted users.'
        },
        log,
        {
          title: 'Brute Force activity',
          message: `${failedLoginCount} authentication failures detected from ${log.sourceIP} within 5 minutes.`,
          evidence: {
            threshold: failedLoginThreshold,
            recentAttempts: failedLoginCount,
            relatedLogs: recent5m.slice(0, 10).map(item => item._id)
          }
        }
      )
    });
  }

  if (effectiveAttackType !== 'Brute Force') {
    const relatedOtherLogs = recent10m.filter(item => {
      const text = `${item.attackType} ${item.description || ''} ${item.userAgent || ''}`;
      const itemAttackType = SQLI_PATTERN.test(text)
        ? 'SQL Injection'
        : XSS_PATTERN.test(text)
          ? 'XSS'
          : item.attackType;
      return itemAttackType === effectiveAttackType;
    });
    const otherAlertCount = relatedOtherLogs.length;

    if (otherAlertCount >= otherAlertsThreshold) {
      const otherRule = otherAttackRule(effectiveAttackType);
      detections.push({
        id: otherRule.id,
        name: otherRule.name,
        severity: otherRule.severity,
        mitreTechnique: otherRule.mitreTechnique,
        confidence: otherRule.confidence,
        windowMinutes: 10,
        riskScore: otherRule.riskScore,
        recommendedAction: otherRule.recommendedAction,
        alert: makeAlert(
          {
            id: otherRule.id,
            name: otherRule.name,
            severity: otherRule.severity,
            mitreTechnique: otherRule.mitreTechnique,
            recommendedAction: otherRule.recommendedAction
          },
          { ...log, attackType: effectiveAttackType },
          {
            title: `${otherRule.name} detected`,
            message: `${otherAlertCount} ${effectiveAttackType} log${otherAlertCount === 1 ? '' : 's'} detected from ${log.sourceIP} within 10 minutes.`,
            evidence: {
              threshold: otherAlertsThreshold,
              recentAttempts: otherAlertCount,
              sample: log.description,
              relatedLogs: relatedOtherLogs.slice(0, 10).map(item => item._id)
            }
          }
        )
      });
    }
  }

  return detections;
}

function incidentCorrelationTag(detection, log) {
  return `${AUTO_SOURCE_TAG}:${detection.id}:${log.sourceIP}`;
}

async function createOrUpdateIncident(log, detection, userId, settings = DEFAULT_PIPELINE_SETTINGS) {
  const severityEscalationEnabled = settings.incidentConfig?.severityEscalationEnabled !== false;
  const correlationTag = incidentCorrelationTag(detection, log);
  const relatedCves = relatedCvesForAttack(log.attackType || detection.alert?.title || detection.alert?.message);
  const cveLines = relatedCves.length ? [`Related CVEs: ${relatedCves.join(', ')}`] : [];
  const commonFields = {
    title: incidentTitleForAlert(detection.alert),
    description: [
      detection.alert.message,
      '',
      `Source IP: ${log.sourceIP}`,
      `Target: ${log.targetSystem}`,
      `Severity: ${detection.alert.severity.toUpperCase()}`,
      `MITRE Technique: ${detection.alert.mitreTechnique}`,
      ...cveLines,
      `Evidence: ${JSON.stringify(detection.alert.evidence)}`
    ].join('\n'),
    severity: detection.alert.severity,
    status: 'open',
    category: incidentCategoryForAlert(detection.alert),
    sourceIP: log.sourceIP,
    affectedSystems: [log.targetSystem],
    createdBy: userId,
    relatedLogs: [log._id],
    relatedCves,
    impact: detection.alert.severity,
    priority: detection.alert.severity,
    tags: [AUTO_INCIDENT_TAG, correlationTag, detection.id, log.attackType]
      .map(tag => sanitizeString(tag))
      .filter(Boolean),
    threatIntel: {
      riskScore: detection.riskScore,
      confidence: detection.confidence,
      mitreTechnique: detection.mitreTechnique,
      recommendedAction: detection.recommendedAction
    }
  };

  let incident = await Incident.findOne({
    sourceIP: log.sourceIP,
    status: { $in: ['open', 'in_progress'] },
    tags: correlationTag
  });

  const created = !incident;

  if (!incident) {
    incident = await Incident.create(commonFields);
    await incident.addTimelineEvent(
      'Auto-created from threat detection',
      userId,
      `${detection.alert.title} linked from ${log.attackType} on ${log.targetSystem}`
    );
  } else {
    incident.description = `${incident.description}\n\n[Auto-linked] ${detection.alert.message}`;
    if (severityEscalationEnabled) {
      incident.severity = detection.alert.severity;
      incident.priority = detection.alert.severity;
      incident.impact = detection.alert.severity;
    }
    incident.threatIntel = {
      ...(incident.threatIntel || {}),
      riskScore: Math.max(Number(incident.threatIntel?.riskScore || 0), detection.riskScore),
      confidence: Math.max(Number(incident.threatIntel?.confidence || 0), detection.confidence),
      mitreTechnique: detection.mitreTechnique,
      recommendedAction: detection.recommendedAction
    };
    incident.tags = Array.from(new Set([...(incident.tags || []), AUTO_INCIDENT_TAG, correlationTag, detection.id]));
    incident.relatedLogs = Array.from(new Set([...(incident.relatedLogs || []).map(String), String(log._id)]));
    await incident.addTimelineEvent(
      'Auto-linked threat detection',
      userId,
      `${detection.alert.title} matched again for ${log.sourceIP}`
    );
  }

  return {
    created,
    incident: await Incident.findById(incident._id)
      .populate('createdBy', 'name email')
      .populate('assignedTo', 'name email')
      .populate('relatedLogs', 'timestamp attackType sourceIP severity')
  };
}

async function broadcastDetection(log, detection, alert, incidentResult) {
  if (incidentResult?.incident) {
    const linkedAlert = await Alert.findById(alert._id);
    if (linkedAlert && !linkedAlert.incident) {
      linkedAlert.incident = incidentResult.incident._id;
      await linkedAlert.save();
    }
  }

  realtimeHub.broadcast({
    type: 'alert:new',
    alert: {
      ...alert.toObject(),
      id: String(alert._id)
    }
  });

  if (incidentResult?.incident) {
    realtimeHub.broadcast({
      type: incidentResult.created ? 'incident:new' : 'incident:updated',
      incident: incidentResult.incident
    });
  }

  realtimeHub.broadcast({
    type: 'stats:updated',
    summary: {
      sourceIP: log.sourceIP,
      attackType: log.attackType,
      incidentCreated: Boolean(incidentResult?.created)
    }
  });
}

async function processJob(job) {
  const settings = await getPipelineSettings();
  const detections = await detectThreats(job.log, settings);
  const seriousDetections = detections.filter(detection => ['critical', 'high'].includes(detection.alert.severity));
  const incidentThreshold = Math.max(
    1,
    Number(settings.incidentConfig?.createIncidentAfter) || DEFAULT_PIPELINE_SETTINGS.incidentConfig.createIncidentAfter
  );

  for (const detection of detections) {
    const alert = await persistAlert(job.log, detection, null);
    let incidentResult = null;
    const shouldCreateIncident = (alert.occurrenceCount || 1) >= incidentThreshold;

    if (shouldCreateIncident) {
      incidentResult = await createOrUpdateIncident(job.log, detection, job.userId, settings);
    }
    await broadcastDetection(job.log, detection, alert, incidentResult);
  }

  return {
    log: job.log,
    detections,
    seriousDetections,
    settings: {
      alertConfig: settings.alertConfig,
      incidentConfig: settings.incidentConfig
    }
  };
}

async function runWithRetry(job, attempt = 1) {
  try {
    const result = await processJob(job);
    job.state = 'completed';
    job.result = result;
    return result;
  } catch (error) {
    job.lastError = error.message;
    if (attempt >= JOB_RETRY_LIMIT) {
      job.state = 'failed';
      realtimeHub.broadcast({
        type: 'pipeline:error',
        error: {
          jobId: job.id,
          message: error.message
        }
      });
      throw error;
    }

    job.state = 'retrying';
    const delay = JOB_BASE_BACKOFF_MS * Math.pow(2, attempt - 1);
    await new Promise(resolve => setTimeout(resolve, delay));
    return runWithRetry(job, attempt + 1);
  }
}

function queueLogAnalysis(log, context = {}) {
  const job = {
    id: generateJobId(),
    state: 'queued',
    log,
    userId: context.userId || log.processedBy || null,
    source: context.source || 'api',
    createdAt: new Date().toISOString()
  };

  if (!processorRegistered) {
    processorRegistered = true;
    jobQueue.registerProcessor('threat-analysis', async (payload) => runWithRetry(payload));
  }

  jobQueue.enqueue('threat-analysis', job, {
    attempts: 1,
    backoff: { delay: JOB_BASE_BACKOFF_MS }
  });

  return job;
}

function queueBatchAnalysis(logs = [], context = {}) {
  return logs.map(log => queueLogAnalysis(log, context));
}

module.exports = {
  validateLogPayload,
  queueLogAnalysis,
  queueBatchAnalysis,
  detectThreats
};
