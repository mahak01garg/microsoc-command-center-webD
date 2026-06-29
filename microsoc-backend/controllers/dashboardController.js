const Log = require('../models/Log');
const Incident = require('../models/Incident');
const Analytics = require('../models/Analytics');
const Alert = require('../models/Alert');

const COUNTRY_ALIAS_MAP = {
  us: 'US',
  usa: 'US',
  'u.s.a.': 'US',
  america: 'US',
  'united states': 'US',
  'united states of america': 'US',
  cn: 'CN',
  china: 'CN',
  ru: 'RU',
  russia: 'RU',
  'russian federation': 'RU',
  de: 'DE',
  germany: 'DE',
  in: 'IN',
  india: 'IN',
  br: 'BR',
  brazil: 'BR',
  jp: 'JP',
  japan: 'JP',
  uk: 'UK',
  'united kingdom': 'UK',
  fr: 'FR',
  france: 'FR',
  kr: 'KR',
  korea: 'KR',
  'south korea': 'KR'
};

const normalizeCountryCode = (value) => {
  const raw = String(value || '').trim();
  if (!raw) return 'Unknown';
  return COUNTRY_ALIAS_MAP[raw.toLowerCase()] || raw.toUpperCase();
};

const mergeCountryAttackMap = (countries = []) => {
  const merged = new Map();

  countries.forEach((country) => {
    const code = normalizeCountryCode(country._id || country.country);
    if (!code || code === 'Unknown') return;
    const current = merged.get(code) || {
      country: code,
      count: 0,
      lastSeen: null,
      severityRank: 1
    };
    const count = Number(country.count || 0);
    current.count += count;
    if (!current.lastSeen || new Date(country.lastSeen || 0) > new Date(current.lastSeen || 0)) {
      current.lastSeen = country.lastSeen;
    }
    current.severityRank = Math.max(current.severityRank, Number(country.severityRank || 1));
    merged.set(code, current);
  });

  return Array.from(merged.values())
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
    });
};

// @desc    Get dashboard statistics
// @route   GET /api/dashboard/stats
// @access  Private
exports.getDashboardStats = async (req, res) => {
  try {
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));

    const activeLogQuery = { archived: { $ne: true } };
    const activeIncidentQuery = { archived: { $ne: true } };

    // Get counts in parallel. Dashboard summary cards use the same all-time
    // active dataset as Security Logs/Incidents pages; trend deltas can still
    // compare against recent windows.
    const [
      totalLogs,
      totalLogs7d,
      openIncidents,
      criticalIncidents,
      blockedAttacks,
      avgResponseTime,
      uniqueSources
    ] = await Promise.all([
      // Total active logs
      Log.countDocuments(activeLogQuery),
      
      // Total logs in last 7 days
      Log.countDocuments({ ...activeLogQuery, timestamp: { $gte: sevenDaysAgo } }),
      
      // Open incidents, matching the Incidents page "Open Incidents" card.
      Incident.countDocuments({ ...activeIncidentQuery, status: 'open' }),
      
      // Critical incidents
      Incident.countDocuments({
        ...activeIncidentQuery,
        status: { $in: ['open', 'in_progress'] },
        severity: 'critical'
      }),
      
      // Blocked active attacks
      Log.countDocuments({ ...activeLogQuery, isBlocked: true }),
      
      // Average response time (mock for now)
      Promise.resolve(2.4),
      
      // Unique active sources
      Log.aggregate([
        {
          $match: activeLogQuery
        },
        {
          $group: {
            _id: '$sourceIP'
          }
        },
        {
          $count: 'count'
        }
      ]).then(result => result[0]?.count || 0)
    ]);

    const logStats = await Log.getStatistics('all');
    const severityDistribution = Array.isArray(logStats?.severityDistribution)
      ? logStats.severityDistribution
      : [];
    const criticalLogs = severityDistribution.find(item => item._id === 'critical')?.count || 0;
    const highLogs = severityDistribution.find(item => item._id === 'high')?.count || 0;
    const mediumLogs = severityDistribution.find(item => item._id === 'medium')?.count || 0;
    const alertCount = await Alert.countDocuments({
      deletedAt: { $exists: false }
    });
    const blockedPercentage = totalLogs > 0
      ? Math.round((blockedAttacks / totalLogs) * 100)
      : 0;

    const totalThreatSignals = totalLogs + alertCount + openIncidents;
    const totalSeveritySignals = Math.max(1, criticalLogs + highLogs + mediumLogs);
    const criticalRatio = criticalLogs / totalSeveritySignals;
    const highRatio = highLogs / totalSeveritySignals;
    const mediumRatio = mediumLogs / totalSeveritySignals;
    const logPressure = Math.round(
      (criticalRatio * 45) +
      (highRatio * 25) +
      (mediumRatio * 12)
    );
    const responsePressure = Math.min(35, openIncidents * 5 + criticalIncidents * 8 + Math.round(Math.min(12, alertCount * 1.5)));
    const resilienceBonus = Math.min(15, Math.round(blockedPercentage / 7)) + Math.min(10, Math.round(uniqueSources / 20));
    const baseScore = 92;

    const recentDailyAverage = totalLogs7d > 0 ? totalLogs7d / 7 : 0;
    const logsChange = recentDailyAverage > 0
      ? Math.round(((totalLogs - recentDailyAverage) / recentDailyAverage) * 100)
      : 0;
    const securityScore = Math.max(
      totalThreatSignals > 0 ? 20 : 45,
      Math.min(
        100,
        baseScore
          - logPressure
          - responsePressure
          + resilienceBonus
          + (totalThreatSignals > 0 ? 4 : 0)
      )
    );


    const stats = [
      {
        icon: 'fa-shield-virus',
        title: 'Security Score',
        value: `${securityScore}/100`,
        change: securityScore >= 80 ? '+Good' : '-Needs Attention',
        changeType: securityScore >= 80 ? 'positive' : 'negative',
        color: '#20c997'  
      },
      {
        icon: 'fa-broadcast-tower',
        title: 'Total Logs',
        value: totalLogs.toLocaleString(),
        change: `${logsChange > 0 ? '+' : ''}${logsChange}%`,
        changeType: logsChange > 0 ? 'negative' : 'positive',
        color: '#007bff'
      },
      {
        icon: 'fa-exclamation-triangle',
        title: 'Open Incidents',
        value: openIncidents,
        change: openIncidents > 10 ? '+2' : '-1',
        changeType: openIncidents > 10 ? 'negative' : 'positive',
        color: '#dc3545'
      },
      {
        icon: 'fa-skull-crossbones',
        title: 'Critical Incidents',
        value: criticalIncidents,
        change: criticalIncidents > 0 ? '+1' : '0',
        changeType: criticalIncidents > 0 ? 'negative' : 'positive',
        color: '#fd7e14'
      },
      {
        icon: 'fa-clock',
        title: 'Avg Response Time',
        value: `${avgResponseTime}h`,
        change: '-0.5h',
        changeType: 'positive',
        color: '#28a745'
      },
      {
        icon: 'fa-shield-alt',
        title: 'Attack Prevention',
        value: `${blockedPercentage}%`,
        change: '+8%',
        changeType: 'positive',
        color: '#17a2b8'
      },
      {
        icon: 'fa-ban',
        title: 'Blocked Attacks',
        value: blockedAttacks.toLocaleString(),
        change: `${blockedPercentage}% blocked`,
        changeType: blockedAttacks > 0 ? 'positive' : 'negative',
        color: '#28a745'
      }
    ];

    res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get dashboard stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get real-time data
// @route   GET /api/dashboard/realtime
// @access  Private
exports.getRealtimeData = async (req, res) => {
  try {
    // Get recent logs (last 30 minutes)
    const thirtyMinutesAgo = new Date(Date.now() - (30 * 60 * 1000));
    
    const recentLogs = await Log.find({
      timestamp: { $gte: thirtyMinutesAgo }
    })
    .sort({ timestamp: -1 })
    .limit(20)
    .select('timestamp attackType sourceIP severity country description isBlocked');

    // Get recent incidents
    const recentIncidents = await Incident.find({
      status: { $in: ['open', 'in_progress'] }
    })
    .sort({ updatedAt: -1 })
    .limit(5)
    .populate('assignedTo', 'name')
    .select('title severity status assignedTo updatedAt');

    const activeLogQuery = { archived: { $ne: true } };

    const topAttackers = await Log.aggregate([
      {
        $match: activeLogQuery
      },
      {
        $group: {
          _id: '$sourceIP',
          count: { $sum: 1 },
          lastSeen: { $max: '$timestamp' },
          country: { $first: '$country' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    const countryAttackMap = await Log.aggregate([
      {
        $match: {
          ...activeLogQuery,
          country: { $exists: true, $nin: [null, ''] }
        }
      },
      {
        $group: {
          _id: '$country',
          count: { $sum: 1 },
          lastSeen: { $max: '$timestamp' }
        }
      },
      { $sort: { count: -1, lastSeen: -1 } }
    ]);

    // Format attack map data
    const attackMapData = topAttackers.map(attacker => ({
      ip: attacker._id,
      count: attacker.count,
      country: attacker.country,
      lastSeen: attacker.lastSeen
    }));

    const countryAttackMapData = mergeCountryAttackMap(countryAttackMap);

    res.status(200).json({
      success: true,
      realtimeData: {
        recentLogs,
        recentIncidents,
        topAttackers: attackMapData,
        countryAttackMap: countryAttackMapData,
        lastUpdated: new Date()
      }
    });
  } catch (error) {
    console.error('Get realtime data error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get all-time active attack map data
// @route   GET /api/dashboard/attack-map
// @access  Private
exports.getAttackMap = async (req, res) => {
  try {
    const activeLogQuery = {
      archived: { $ne: true },
      country: { $exists: true, $nin: [null, '', 'Unknown'] }
    };

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

    const [countryAttackMap, totalLogs] = await Promise.all([
      Log.aggregate([
        { $match: activeLogQuery },
        {
          $group: {
            _id: '$country',
            count: { $sum: 1 },
            lastSeen: { $max: '$timestamp' },
            severityRank: { $max: severityRankExpression }
          }
        },
        { $sort: { count: -1, lastSeen: -1 } }
      ]),
      Log.countDocuments({ archived: { $ne: true } })
    ]);

    res.status(200).json({
      success: true,
      totalLogs,
      countryAttackMap: mergeCountryAttackMap(countryAttackMap)
    });
  } catch (error) {
    console.error('Get attack map error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get recent activity
// @route   GET /api/dashboard/activity
// @access  Private
exports.getRecentActivity = async (req, res) => {
  try {
    const oneHourAgo = new Date(Date.now() - (60 * 60 * 1000));

    // Get recent logs
    const recentLogs = await Log.find({
      timestamp: { $gte: oneHourAgo }
    })
    .sort({ timestamp: -1 })
    .limit(15)
    .select('timestamp attackType sourceIP severity description isBlocked');

    // Get recent incidents
    const recentIncidents = await Incident.find({
      updatedAt: { $gte: oneHourAgo }
    })
    .sort({ updatedAt: -1 })
    .limit(10)
    .populate('assignedTo', 'name')
    .populate('createdBy', 'name')
    .select('title severity status assignedTo createdBy updatedAt');

    // Format activity timeline
    const activities = [];

    // Add log activities
    recentLogs.forEach(log => {
      activities.push({
        type: 'log',
        timestamp: log.timestamp,
        title: `${log.attackType} Detected`,
        description: log.description,
        severity: log.severity,
        sourceIP: log.sourceIP,
        isBlocked: log.isBlocked
      });
    });

    // Add incident activities
    recentIncidents.forEach(incident => {
      activities.push({
        type: 'incident',
        timestamp: incident.updatedAt,
        title: `Incident: ${incident.title}`,
        description: `Status changed to ${incident.status}`,
        severity: incident.severity,
        assignedTo: incident.assignedTo?.name,
        createdBy: incident.createdBy?.name
      });
    });

    // Sort by timestamp
    activities.sort((a, b) => b.timestamp - a.timestamp);

    res.status(200).json({
      success: true,
      activities: activities.slice(0, 20) // Limit to 20 activities
    });
  } catch (error) {
    console.error('Get recent activity error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get recent alerts
// @route   GET /api/dashboard/alerts
// @access  Private
exports.getRecentAlerts = async (req, res) => {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
    const alerts = await Alert.find({
      deletedAt: { $exists: false },
      lastSeen: { $gte: twentyFourHoursAgo }
    })
      .sort({ severity: 1, lastSeen: -1 })
      .limit(15)
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity description isBlocked country');

    const formattedAlerts = alerts.map(alert => ({
      type: alert.incident ? 'incident' : 'log',
      id: alert._id,
      timestamp: alert.lastSeen || alert.createdAt,
      title: alert.title,
      description: alert.description,
      severity: alert.severity,
      source: alert.sourceIP,
      country: alert.log?.country,
      isBlocked: alert.log?.isBlocked,
      status: alert.status,
      assignedTo: alert.incident?.assignedTo?.name,
      requiresAction: ['new', 'in_progress'].includes(alert.status),
      occurrenceCount: alert.occurrenceCount,
      attackType: alert.attackType,
      ruleId: alert.ruleId
    }));

    const alertsRequiringAction = formattedAlerts.filter(alert => alert.requiresAction).length;

    res.status(200).json({
      success: true,
      alerts: formattedAlerts,
      summary: {
        total: formattedAlerts.length,
        critical: formattedAlerts.filter(a => a.severity === 'critical').length,
        requiringAction: alertsRequiringAction,
        lastUpdated: new Date()
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
