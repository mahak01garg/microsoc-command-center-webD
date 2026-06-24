const Log = require('../models/Log');
const Incident = require('../models/Incident');
const Analytics = require('../models/Analytics');
const Alert = require('../models/Alert');

// @desc    Get dashboard statistics
// @route   GET /api/dashboard/stats
// @access  Private
exports.getDashboardStats = async (req, res) => {
  try {
    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    const sevenDaysAgo = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));

    // Get counts in parallel
    const [
      totalLogs24h,
      totalLogs7d,
      activeIncidents,
      criticalIncidents,
      blockedAttacks24h,
      avgResponseTime,
      uniqueSources24h
    ] = await Promise.all([
      // Total logs in last 24 hours
      Log.countDocuments({ timestamp: { $gte: twentyFourHoursAgo } }),
      
      // Total logs in last 7 days
      Log.countDocuments({ timestamp: { $gte: sevenDaysAgo } }),
      
      // Active incidents
      Incident.countDocuments({ status: { $in: ['open', 'in_progress'] } }),
      
      // Critical incidents
      Incident.countDocuments({ 
        status: { $in: ['open', 'in_progress'] },
        severity: 'critical'
      }),
      
      // Blocked attacks in last 24 hours
      Log.countDocuments({ 
        timestamp: { $gte: twentyFourHoursAgo },
        isBlocked: true
      }),
      
      // Average response time (mock for now)
      Promise.resolve(2.4),
      
      // Unique sources in last 24 hours
      Log.aggregate([
        {
          $match: {
            timestamp: { $gte: twentyFourHoursAgo }
          }
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

    const logStats24h = await Log.getStatistics('24h');
    const severityDistribution = Array.isArray(logStats24h?.severityDistribution)
      ? logStats24h.severityDistribution
      : [];
    const criticalLogs24h = severityDistribution.find(item => item._id === 'critical')?.count || 0;
    const highLogs24h = severityDistribution.find(item => item._id === 'high')?.count || 0;
    const mediumLogs24h = severityDistribution.find(item => item._id === 'medium')?.count || 0;
    const alertCount24h = await Alert.countDocuments({
      deletedAt: { $exists: false },
      lastSeen: { $gte: twentyFourHoursAgo }
    });
    const blockedPercentage = totalLogs24h > 0 
      ? Math.round((blockedAttacks24h / totalLogs24h) * 100)
      : 0;

    const totalThreatSignals = totalLogs24h + alertCount24h + activeIncidents;
    const totalSeveritySignals = Math.max(1, criticalLogs24h + highLogs24h + mediumLogs24h);
    const criticalRatio = criticalLogs24h / totalSeveritySignals;
    const highRatio = highLogs24h / totalSeveritySignals;
    const mediumRatio = mediumLogs24h / totalSeveritySignals;
    const logPressure = Math.round(
      (criticalRatio * 45) +
      (highRatio * 25) +
      (mediumRatio * 12)
    );
    const responsePressure = Math.min(35, activeIncidents * 5 + criticalIncidents * 8 + Math.round(Math.min(12, alertCount24h * 1.5)));
    const resilienceBonus = Math.min(15, Math.round(blockedPercentage / 7)) + Math.min(10, Math.round(uniqueSources24h / 20));
    const baseScore = 92;

    const logsChange = totalLogs7d > 0
      ? Math.round(((totalLogs24h - (totalLogs7d / 7)) / (totalLogs7d / 7)) * 100)
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
        title: 'Total Logs (24h)',
        value: totalLogs24h.toLocaleString(),
        change: `${logsChange > 0 ? '+' : ''}${logsChange}%`,
        changeType: logsChange > 0 ? 'negative' : 'positive',
        color: '#007bff'
      },
      {
        icon: 'fa-exclamation-triangle',
        title: 'Active Incidents',
        value: activeIncidents,
        change: activeIncidents > 10 ? '+2' : '-1',
        changeType: activeIncidents > 10 ? 'negative' : 'positive',
        color: '#dc3545'
      },
      {
        icon: 'fa-skull-crossbones',
        title: 'Critical Threats',
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
        icon: 'fa-network-wired',
        title: 'Unique Sources',
        value: uniqueSources24h,
        change: '+3',
        changeType: 'negative',
        color: '#6c757d'
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

    // Get top attackers for today
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const topAttackers = await Log.aggregate([
      {
        $match: {
          timestamp: { $gte: todayStart }
        }
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
          timestamp: { $gte: todayStart },
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

    const countryAttackMapData = countryAttackMap.map(country => ({
      country: country._id,
      count: country.count,
      lastSeen: country.lastSeen
    }));

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
