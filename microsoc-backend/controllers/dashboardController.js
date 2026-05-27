const Log = require('../models/Log');
const Incident = require('../models/Incident');
const Analytics = require('../models/Analytics');

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

    // Calculate percentages
    const blockedPercentage = totalLogs24h > 0 
      ? Math.round((blockedAttacks24h / totalLogs24h) * 100)
      : 0;

    const logsChange = totalLogs7d > 0
      ? Math.round(((totalLogs24h - (totalLogs7d / 7)) / (totalLogs7d / 7)) * 100)
      : 0;

    const stats = [
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

    // Format attack map data
    const attackMapData = topAttackers.map(attacker => ({
      ip: attacker._id,
      count: attacker.count,
      country: attacker.country,
      lastSeen: attacker.lastSeen
    }));

    res.status(200).json({
      success: true,
      realtimeData: {
        recentLogs,
        recentIncidents,
        topAttackers: attackMapData,
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

    // Get critical and high severity logs
    const criticalLogs = await Log.find({
      timestamp: { $gte: twentyFourHoursAgo },
      severity: { $in: ['critical', 'high'] }
    })
    .sort({ timestamp: -1 })
    .limit(10)
    .select('timestamp attackType sourceIP severity description isBlocked country');

    // Get open critical incidents
    const criticalIncidents = await Incident.find({
      severity: 'critical',
      status: { $in: ['open', 'in_progress'] }
    })
    .sort({ updatedAt: -1 })
    .limit(5)
    .populate('assignedTo', 'name')
    .select('title description severity status assignedTo createdAt');

    // Format alerts
    const alerts = [];

    // Add log alerts
    criticalLogs.forEach(log => {
      alerts.push({
        type: 'log',
        id: log._id,
        timestamp: log.timestamp,
        title: `${log.severity.toUpperCase()}: ${log.attackType}`,
        description: log.description,
        severity: log.severity,
        source: log.sourceIP,
        country: log.country,
        isBlocked: log.isBlocked,
        requiresAction: !log.isBlocked && log.severity === 'critical'
      });
    });

    // Add incident alerts
    criticalIncidents.forEach(incident => {
      alerts.push({
        type: 'incident',
        id: incident._id,
        timestamp: incident.createdAt,
        title: `CRITICAL INCIDENT: ${incident.title}`,
        description: incident.description,
        severity: incident.severity,
        status: incident.status,
        assignedTo: incident.assignedTo?.name,
        requiresAction: incident.status === 'open'
      });
    });

    // Sort by timestamp and severity
    alerts.sort((a, b) => {
      // Critical first
      if (a.severity === 'critical' && b.severity !== 'critical') return -1;
      if (b.severity === 'critical' && a.severity !== 'critical') return 1;
      
      // Then by timestamp
      return b.timestamp - a.timestamp;
    });

    // Count alerts requiring action
    const alertsRequiringAction = alerts.filter(alert => alert.requiresAction).length;

    res.status(200).json({
      success: true,
      alerts: alerts.slice(0, 15), // Limit to 15 alerts
      summary: {
        total: alerts.length,
        critical: alerts.filter(a => a.severity === 'critical').length,
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