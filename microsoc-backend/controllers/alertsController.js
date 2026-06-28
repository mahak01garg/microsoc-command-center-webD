const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const SystemSettings = require('../models/SystemSettings');
const User = require('../models/User');
const realtimeHub = require('../utils/realtimeHub');
const { recordAuditEvent } = require('../utils/auditLogger');

const AUTO_INCIDENT_TAG = 'auto-alert-correlation';
const DEFAULT_INCIDENT_THRESHOLD = 3;
const INCIDENT_DESCRIPTION_LIMIT = 1900;
const INCIDENT_TITLE_LIMIT = 190;

function relatedCvesForAttack(value = '') {
  const key = String(value || '').toLowerCase();
  if (key.includes('microsoft outlook exploit') || key.includes('outlook exploit')) return ['CVE-2023-23397'];
  if (key.includes('apache struts exploit') || key.includes('struts exploit')) return ['CVE-2017-5638'];
  if (key.includes('exchange server exploit') || key.includes('exchange exploit') || key.includes('proxylogon') || key.includes('proxyshell')) return ['CVE-2021-26855', 'CVE-2021-34473'];
  if (key.includes('log4shell exploit') || key.includes('log4j exploit') || key.includes('log4shell')) return ['CVE-2021-44228'];
  return [];
}

function isSystemGeneratedAlert(alert = {}) {
  const source = String(alert.metadata?.source || alert.source || '').toLowerCase();
  const tags = Array.isArray(alert.tags) ? alert.tags.map(tag => String(tag).toLowerCase()) : [];
  return Boolean(alert.metadata?.systemGenerated)
    || source.includes('live')
    || source.includes('auto')
    || tags.includes('auto-alert-correlation')
    || tags.includes('system-generated');
}

function buildTimeWindow(timeRange = '24h') {
  const now = new Date();
  switch (timeRange) {
    case 'all':
      return null;
    case '1h':
      return new Date(now.getTime() - (60 * 60 * 1000));
    case '24h':
      return new Date(now.getTime() - (24 * 60 * 60 * 1000));
    case '7d':
      return new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
    case '30d':
      return new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
    default:
      return new Date(now.getTime() - (24 * 60 * 60 * 1000));
  }
}

function buildQuery(req) {
  const {
    status,
    severity,
    sourceIP,
    attackType,
    search,
    timeRange = '24h'
  } = req.query;

  const query = {
    deletedAt: { $exists: false }
  };

  const startDate = buildTimeWindow(timeRange);
  if (startDate) {
    query.lastSeen = { $gte: startDate };
  }

  if (status && status !== 'all') {
    query.status = Array.isArray(status) ? { $in: status } : status;
  }

  if (severity && severity !== 'all') {
    query.severity = Array.isArray(severity) ? { $in: severity } : severity;
  }

  if (sourceIP) {
    query.sourceIP = { $regex: sourceIP, $options: 'i' };
  }

  if (attackType) {
    query.attackType = { $regex: attackType, $options: 'i' };
  }

  if (search) {
    query.$or = [
      { title: { $regex: search, $options: 'i' } },
      { description: { $regex: search, $options: 'i' } },
      { sourceIP: { $regex: search, $options: 'i' } },
      { targetSystem: { $regex: search, $options: 'i' } },
      { attackType: { $regex: search, $options: 'i' } }
    ];
  }

  return { query, timeRange };
}

function normalizeIncidentSeverity(severity) {
  const value = String(severity || 'medium').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(value) ? value : 'medium';
}

function incidentCategoryForAlert(alert = {}) {
  const attackType = String(alert.attackType || alert.title || '').toLowerCase();
  if (attackType.includes('malware') || attackType.includes('ransomware')) return 'malware';
  if (attackType.includes('phishing') || attackType.includes('credential')) return 'phishing';
  if (attackType.includes('ddos')) return 'ddos';
  if (attackType.includes('insider')) return 'insider_threat';
  if (attackType.includes('exfiltration') || attackType.includes('data')) return 'data_breach';
  if (attackType.includes('scan') || attackType.includes('injection') || attackType.includes('xss')) return 'vulnerability';
  return 'other';
}

function sanitizeTag(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9:_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50);
}

function truncateText(value, limit) {
  const text = String(value || '').trim();
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - 14)).trim()}... [truncated]`;
}

function normalizeIncidentTags(tags = []) {
  return [...new Set(tags.map(sanitizeTag).filter(Boolean))];
}

function normalizeIncidentText(value, fallback, limit) {
  return truncateText(value || fallback, limit);
}

function isIPv4(value) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(String(value || ''));
}

function getAlertCorrelationScope(alert = {}) {
  const attackType = String(alert.attackType || alert.title || '').toLowerCase();
  const targetSystem = String(alert.targetSystem || '').trim();
  const sourceIP = String(alert.sourceIP || '').trim();
  const sourceScopedAttacks = [
    'brute force',
    'port scan',
    'credential stuffing',
    'password spraying'
  ];
  const targetScopedAttacks = [
    'sql injection',
    'xss',
    'cross-site scripting',
    'ddos',
    'microsoft outlook exploit',
    'outlook exploit',
    'apache struts exploit',
    'exchange server exploit',
    'log4shell exploit',
    'log4j exploit'
  ];

  if (targetScopedAttacks.some(type => attackType.includes(type)) && targetSystem) {
    return {
      field: 'targetSystem',
      value: targetSystem,
      label: attackType.includes('xss') || attackType.includes('cross-site scripting') ? 'web application/endpoint'
        : attackType.includes('sql') ? 'API/endpoint'
          : attackType.includes('outlook') ? 'mail server'
            : attackType.includes('struts') ? 'web server'
              : attackType.includes('exchange') ? 'Exchange server'
                : 'target server/service'
    };
  }

  if (sourceScopedAttacks.some(type => attackType.includes(type)) && sourceIP) {
    return { field: 'sourceIP', value: sourceIP, label: 'source IP' };
  }

  if (targetSystem) return { field: 'targetSystem', value: targetSystem, label: 'target system' };
  if (sourceIP) return { field: 'sourceIP', value: sourceIP, label: 'source IP' };
  return { field: null, value: '', label: 'source or target' };
}

function buildSimilarityQuery(alert) {
  const ruleKey = alert.ruleId || alert.attackType || 'manual-alert';
  const scope = getAlertCorrelationScope(alert);
  const query = {
    deletedAt: { $exists: false }
  };

  if (alert.attackType) {
    query.attackType = alert.attackType;
  }

  if (scope.field && scope.value) {
    query[scope.field] = scope.value;
  }

  return {
    query,
    scope,
    ruleKey: sanitizeTag(ruleKey),
    correlationTag: sanitizeTag(`${AUTO_INCIDENT_TAG}:${alert.attackType || 'attack'}:${scope.field || 'scope'}:${scope.value || 'any'}`)
  };
}

async function resolveIncidentCreator(userId) {
  if (userId && User.db.base.Types.ObjectId.isValid(String(userId))) {
    return userId;
  }

  const primaryAdmin = await User.findOne({ email: User.getPrimaryAdminEmail() }).select('_id').lean();
  if (primaryAdmin?._id) return primaryAdmin._id;

  const anyAdmin = await User.findOne({ role: 'admin' }).select('_id').lean();
  if (anyAdmin?._id) return anyAdmin._id;

  throw new Error('Cannot create correlated incident because no admin user exists for createdBy');
}

async function correlateAlertToIncident(alert, userId, req) {
  const settings = await SystemSettings.getSingleton();
  const createdBy = await resolveIncidentCreator(userId);
  const threshold = Math.max(1, Number(settings.incidentConfig?.createIncidentAfter) || DEFAULT_INCIDENT_THRESHOLD);
  const severityEscalationEnabled = settings.incidentConfig?.severityEscalationEnabled !== false;
  const { query, scope, ruleKey, correlationTag } = buildSimilarityQuery(alert);
  const similarAlerts = await Alert.find(query).sort({ lastSeen: 1 });
  const similarAlertCount = similarAlerts.reduce(
    (sum, item) => sum + Math.max(1, Number(item.occurrenceCount || 1)),
    0
  );

  if (similarAlertCount < threshold) {
    return { created: false, incident: null, similarAlertCount, threshold };
  }

  const sourceIPs = [...new Set(similarAlerts.map(item => item.sourceIP).filter(Boolean))];
  const rawSourceIP = sourceIPs.length === 1 ? sourceIPs[0] : undefined;
  const sourceIP = isIPv4(rawSourceIP) ? rawSourceIP : undefined;
  const affectedSystems = [...new Set(similarAlerts.map(item => item.targetSystem).filter(Boolean))];
  const relatedLogs = [...new Set(similarAlerts.map(item => item.log).filter(Boolean).map(String))];
  const highestSeverity = similarAlerts.some(item => item.severity === 'critical')
    ? 'critical'
    : similarAlerts.some(item => item.severity === 'high')
      ? 'high'
      : normalizeIncidentSeverity(alert.severity);

  const incidentQuery = {
    status: { $in: ['open', 'in_progress'] },
    tags: correlationTag
  };
  if (sourceIP) incidentQuery.sourceIP = sourceIP;

  let incident = await Incident.findOne(incidentQuery);

  const created = !incident;
  const scopeText = scope.value ? `${scope.label} ${scope.value}` : 'matched source/target';
  const title = `Repeated ${alert.attackType || alert.ruleId || 'security'} alerts for ${scopeText}`;
  const relatedCves = relatedCvesForAttack(`${alert.attackType || ''} ${alert.title || ''} ${alert.description || ''}`);
  const cveLines = relatedCves.length ? [`Related CVEs: ${relatedCves.join(', ')}`] : [];

  if (!incident) {
    incident = await Incident.create({
      title: normalizeIncidentText(title, 'Repeated security alerts', INCIDENT_TITLE_LIMIT),
      description: normalizeIncidentText([
        `${similarAlertCount} similar alert occurrence(s) reached the incident threshold (${threshold}).`,
        '',
        `Rule: ${alert.ruleId || 'N/A'}`,
        `Attack Type: ${alert.attackType || 'Unknown'}`,
        `Correlation: same ${scope.label}${scope.value ? ` (${scope.value})` : ''}`,
        ...cveLines,
        `Source IPs: ${sourceIPs.join(', ') || 'Unknown'}`,
        `Affected Systems: ${affectedSystems.join(', ') || 'Unknown'}`,
        `Latest Alert: ${alert.title}`
      ].join('\n'), 'Similar alerts reached the incident threshold.', INCIDENT_DESCRIPTION_LIMIT),
      severity: highestSeverity,
      status: 'open',
      category: incidentCategoryForAlert(alert),
      sourceIP,
      affectedSystems,
      createdBy,
      relatedLogs,
      relatedCves,
      impact: highestSeverity,
      priority: highestSeverity,
      tags: normalizeIncidentTags([AUTO_INCIDENT_TAG, correlationTag, ruleKey, alert.attackType || 'alert']),
      threatIntel: {
        riskScore: Math.min(100, 45 + similarAlertCount * 10),
        confidence: Math.min(95, 55 + similarAlertCount * 8),
        mitreTechnique: alert.mitreTechnique || 'Unknown',
        recommendedAction: 'Investigate repeated correlated alerts and validate containment.'
      }
    });
    await incident.addTimelineEvent(
      'Auto-created from similar alerts',
      createdBy,
      `${similarAlertCount} alert occurrence(s) matched ${alert.ruleId || alert.attackType || 'rule'} by same ${scope.label}${scope.value ? ` (${scope.value})` : ''}.`
    );
  } else {
    const existingRelatedLogs = (incident.relatedLogs || []).map(String);
    const nextRelatedLogs = [...new Set([...existingRelatedLogs, ...relatedLogs])];
    const nextAffectedSystems = [...new Set([...(incident.affectedSystems || []), ...affectedSystems])];
    const shouldEscalate = severityEscalationEnabled && (
      incident.severity !== highestSeverity ||
      incident.priority !== highestSeverity ||
      incident.impact !== highestSeverity
    );
    const hasNewLinks = similarAlerts.some(item => String(item.incident || '') !== String(incident._id))
      || nextRelatedLogs.length !== existingRelatedLogs.length
      || nextAffectedSystems.length !== (incident.affectedSystems || []).length;

    if (severityEscalationEnabled) {
      incident.severity = highestSeverity;
      incident.priority = highestSeverity;
      incident.impact = highestSeverity;
    }
    incident.affectedSystems = nextAffectedSystems;
    incident.relatedLogs = nextRelatedLogs;
    incident.description = normalizeIncidentText(incident.description, 'Correlated alert incident.', INCIDENT_DESCRIPTION_LIMIT);
    incident.tags = normalizeIncidentTags([...(incident.tags || []), AUTO_INCIDENT_TAG, correlationTag, ruleKey]);
    if (hasNewLinks || shouldEscalate) {
      await incident.addTimelineEvent(
        'Auto-updated from similar alert',
        createdBy,
        `${alert.title} matched existing correlated incident.`
      );
    } else {
      await incident.save();
    }
  }

  await Alert.updateMany(
    { _id: { $in: similarAlerts.map(item => item._id) } },
    { $set: { incident: incident._id } }
  );

  const populatedIncident = await Incident.findById(incident._id)
    .populate('createdBy', 'name email')
    .populate('assignedTo', 'name email')
    .populate('relatedLogs', 'timestamp attackType sourceIP severity');

  realtimeHub.broadcast({
    type: created ? 'incident:new' : 'incident:updated',
    incident: populatedIncident
  });
  realtimeHub.broadcast({
    type: 'stats:updated',
    summary: {
      sourceIP,
      attackType: alert.attackType,
      incidentCreated: created
    }
  });

  if (req) {
    await recordAuditEvent(req, {
      systemAction: true,
      action: created ? 'Auto Incident Created' : 'Auto Incident Updated',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(populatedIncident._id),
      targetLabel: populatedIncident.title,
      details: `${created ? 'Created' : 'Updated'} incident from correlated ${alert.attackType || 'security'} alerts`,
      metadata: {
        alertId: String(alert._id || alert.id || ''),
        attackType: alert.attackType,
        similarAlertCount,
        threshold,
        severityEscalationEnabled,
        correlation: scope
      }
    });
  }

  return { created, incident: populatedIncident, similarAlertCount, threshold };
}

async function correlateExistingAlertsToIncidents(userId, req, options = {}) {
  const limit = Math.min(1000, Math.max(1, Number(options.limit) || 500));
  const alerts = await Alert.find({
    deletedAt: { $exists: false },
    status: { $in: ['new', 'in_progress'] }
  })
    .sort({ lastSeen: -1 })
    .limit(limit);

  const seen = new Set();
  const results = [];

  for (const alert of alerts) {
    const { query } = buildSimilarityQuery(alert);
    const key = JSON.stringify(query);
    if (seen.has(key)) continue;
    seen.add(key);

    const result = await correlateAlertToIncident(alert, userId, req);
    if (result?.incident) {
      results.push({
        created: Boolean(result.created),
        incidentId: result.incident._id || result.incident.id,
        title: result.incident.title,
        similarAlertCount: result.similarAlertCount,
        threshold: result.threshold
      });
    }
  }

  return results;
}

exports.getRecentAlerts = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      sortBy = 'lastSeen',
      sortOrder = 'desc'
    } = req.query;

    const { query, timeRange } = buildQuery(req);
    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const limitNumber = Math.min(500, Math.max(1, parseInt(limit, 10) || 50));
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const alerts = await Alert.find(query)
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity')
      .sort(sort)
      .limit(limitNumber)
      .skip((pageNumber - 1) * limitNumber)
      .lean();

    const total = await Alert.countDocuments(query);
    const totalPages = Math.ceil(total / limitNumber);
    const stats = await Alert.getStatistics(timeRange);

    res.status(200).json({
      success: true,
      count: alerts.length,
      total,
      page: pageNumber,
      totalPages,
      alerts: alerts.map(alert => ({ ...alert, id: String(alert._id) })),
      stats,
      incidentCorrelation: {
        createdCount: 0,
        linkedCount: 0,
        incidents: []
      }
    });
  } catch (error) {
    console.error('Get recent alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.getAlertById = async (req, res) => {
  try {
    const alert = await Alert.findOne({
      _id: req.params.id,
      deletedAt: { $exists: false }
    })
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity description')
      .populate('reviewedBy', 'name email')
      .populate('deletedBy', 'name email')
      .populate('notes.user', 'name email');

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    res.status(200).json({
      success: true,
      alert
    });
  } catch (error) {
    console.error('Get alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.getAlertStats = async (req, res) => {
  try {
    const { timeRange = '24h' } = req.query;
    const stats = await Alert.getStatistics(timeRange);
    res.status(200).json({
      success: true,
      stats,
      incidentCorrelation: {
        createdCount: 0,
        linkedCount: 0,
        incidents: []
      }
    });
  } catch (error) {
    console.error('Get alert stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.createAlert = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can create alerts.'
      });
    }

    const alert = await Alert.create({
      ...req.body,
      status: req.body.status || 'new'
    });

    const systemGenerated = isSystemGeneratedAlert(alert);
    await recordAuditEvent(req, {
      systemAction: systemGenerated,
      action: systemGenerated ? 'Alert Auto Generated' : 'Alert Created',
      module: 'alerts',
      targetType: 'Alert',
      targetId: String(alert._id),
      targetLabel: alert.title,
      details: `${systemGenerated ? 'Auto-generated' : 'Created'} alert "${alert.title}"`,
      metadata: {
        severity: alert.severity,
        status: alert.status,
        attackType: alert.attackType,
        sourceIP: alert.sourceIP,
        targetSystem: alert.targetSystem,
        source: alert.metadata?.source || 'manual'
      }
    });

    const incidentResult = await correlateAlertToIncident(alert, req.user.id, req);
    const populatedAlert = await Alert.findById(alert._id)
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity');

    res.status(201).json({
      success: true,
      alert: populatedAlert,
      incident: incidentResult?.incident || null,
      incidentCreated: Boolean(incidentResult?.created),
      similarAlertCount: incidentResult?.similarAlertCount ?? null,
      incidentThreshold: incidentResult?.threshold ?? null
    });
  } catch (error) {
    console.error('Create alert error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
};

exports.correlateAlertToIncident = correlateAlertToIncident;
exports.correlateExistingAlertsToIncidents = correlateExistingAlertsToIncidents;

exports.updateAlert = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can update alerts.'
      });
    }

    const alert = await Alert.findOne({
      _id: req.params.id,
      deletedAt: { $exists: false }
    });

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    const { status, severity, notes, reviewedAt, reviewedBy, ...rest } = req.body;

    Object.assign(alert, rest);

    if (severity) alert.severity = severity;
    if (status) alert.status = status;
    if (Array.isArray(notes) && notes.length) {
      notes.forEach(note => {
        alert.notes.push({
          text: note.text || note,
          user: req.user.id
        });
      });
    }

    if (reviewedAt) alert.reviewedAt = reviewedAt;
    if (reviewedBy) alert.reviewedBy = reviewedBy;

    await alert.save();

    const populated = await Alert.findById(alert._id)
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity');

    res.status(200).json({
      success: true,
      alert: populated
    });
  } catch (error) {
    console.error('Update alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.bulkUpdateAlerts = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can update alerts in bulk.'
      });
    }

    const { ids, status, severity, note } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide alert IDs'
      });
    }

    const alerts = await Alert.find({
      _id: { $in: ids },
      deletedAt: { $exists: false }
    });

    for (const alert of alerts) {
      if (status) alert.status = status;
      if (severity) alert.severity = severity;
      if (note) {
        alert.notes.push({
          text: note,
          user: req.user.id
        });
      }
      await alert.save();
    }

    res.status(200).json({
      success: true,
      count: alerts.length,
      message: `${alerts.length} alerts updated successfully`
    });
  } catch (error) {
    console.error('Bulk update alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.deleteAlert = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can archive alerts.'
      });
    }

    const alert = await Alert.findOne({
      _id: req.params.id,
      deletedAt: { $exists: false }
    });

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    await alert.softDelete(req.user.id, req.body?.reason);

    res.status(200).json({
      success: true,
      message: 'Alert archived successfully'
    });
  } catch (error) {
    console.error('Delete alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
