const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const SystemSettings = require('../models/SystemSettings');
const realtimeHub = require('../utils/realtimeHub');

const AUTO_INCIDENT_TAG = 'auto-alert-correlation';

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

function isIPv4(value) {
  return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(String(value || ''));
}

function buildSimilarityQuery(alert) {
  const ruleKey = alert.ruleId || alert.attackType || 'manual-alert';
  const query = {
    deletedAt: { $exists: false }
  };

  if (alert.ruleId) {
    query.ruleId = alert.ruleId;
  }

  if (alert.attackType) {
    query.attackType = alert.attackType;
  }

  return {
    query,
    ruleKey: sanitizeTag(ruleKey),
    correlationTag: sanitizeTag(`${AUTO_INCIDENT_TAG}:${ruleKey}:${alert.attackType || 'attack'}`)
  };
}

async function correlateAlertToIncident(alert, userId) {
  const settings = await SystemSettings.getSingleton();
  const threshold = Math.max(1, Number(settings.incidentConfig?.createIncidentAfter) || 3);
  const { query, ruleKey, correlationTag } = buildSimilarityQuery(alert);
  const similarAlerts = await Alert.find(query).sort({ lastSeen: 1 });

  if (similarAlerts.length < threshold) {
    return { created: false, incident: null, similarAlertCount: similarAlerts.length, threshold };
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
  const title = `Repeated ${alert.attackType || alert.ruleId || 'security'} alerts${sourceIP ? ` from ${sourceIP}` : ''}`;

  if (!incident) {
    incident = await Incident.create({
      title,
      description: [
        `${similarAlerts.length} similar alerts reached the incident threshold (${threshold}).`,
        '',
        `Rule: ${alert.ruleId || 'N/A'}`,
        `Attack Type: ${alert.attackType || 'Unknown'}`,
        `Source IPs: ${sourceIPs.join(', ') || 'Unknown'}`,
        `Latest Alert: ${alert.title}`
      ].join('\n'),
      severity: highestSeverity,
      status: 'open',
      category: incidentCategoryForAlert(alert),
      sourceIP,
      affectedSystems,
      createdBy: userId,
      relatedLogs,
      impact: highestSeverity,
      priority: highestSeverity,
      tags: [AUTO_INCIDENT_TAG, correlationTag, ruleKey, sanitizeTag(alert.attackType || 'alert')].filter(Boolean),
      threatIntel: {
        riskScore: Math.min(100, 45 + similarAlerts.length * 10),
        confidence: Math.min(95, 55 + similarAlerts.length * 8),
        mitreTechnique: alert.mitreTechnique || 'Unknown',
        recommendedAction: 'Investigate repeated correlated alerts and validate containment.'
      }
    });
    await incident.addTimelineEvent(
      'Auto-created from similar alerts',
      userId,
      `${similarAlerts.length} alerts matched ${alert.ruleId || alert.attackType || 'rule'} from ${sourceIP}.`
    );
  } else {
    incident.severity = highestSeverity;
    incident.priority = highestSeverity;
    incident.impact = highestSeverity;
    incident.affectedSystems = [...new Set([...(incident.affectedSystems || []), ...affectedSystems])];
    incident.relatedLogs = [...new Set([...(incident.relatedLogs || []).map(String), ...relatedLogs])];
    incident.tags = [...new Set([...(incident.tags || []), AUTO_INCIDENT_TAG, correlationTag, ruleKey])];
    await incident.addTimelineEvent(
      'Auto-updated from similar alert',
      userId,
      `${alert.title} matched existing correlated incident.`
    );
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

  return { created, incident: populatedIncident, similarAlertCount: similarAlerts.length, threshold };
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
      stats
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
      stats
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

    const incidentResult = await correlateAlertToIncident(alert, req.user.id);
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
      message: 'Server error'
    });
  }
};

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
