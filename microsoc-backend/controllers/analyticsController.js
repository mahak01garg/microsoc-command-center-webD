const Analytics = require('../models/Analytics');
const Log = require('../models/Log');
const Incident = require('../models/Incident');

// @desc    Get analytics overview
// @route   GET /api/analytics/overview
// @access  Private
exports.getOverview = async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;

    // Get current analytics or generate new
    let analytics = await Analytics.findOne({
      date: {
        $gte: new Date(new Date().setHours(0, 0, 0, 0)),
        $lt: new Date(new Date().setHours(23, 59, 59, 999))
      }
    });

    if (!analytics) {
      analytics = await Analytics.generateDailyAnalytics();
    }

    // Get log statistics for time range
    const logStats = await Log.getStatistics(timeRange);

    // Get incident statistics
    const incidentStats = await Incident.getStatistics();

    res.status(200).json({
      success: true,
      analytics: {
        ...analytics.toObject(),
        logStats,
        incidentStats
      }
    });
  } catch (error) {
    console.error('Get analytics overview error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get attack distribution
// @route   GET /api/analytics/attack-distribution
// @access  Private
exports.getAttackDistribution = async (req, res) => {
  try {
    const { timeRange = '24h' } = req.query;

    const logStats = await Log.getStatistics(timeRange);
    
    const distribution = {
      labels: logStats.attackTypeDistribution?.map(item => item._id) || [],
      datasets: [{
        data: logStats.attackTypeDistribution?.map(item => item.count) || [],
        backgroundColor: [
          '#dc3545', '#fd7e14', '#ffc107', '#28a745',
          '#17a2b8', '#6f42c1', '#e83e8c', '#343a40'
        ]
      }]
    };

    res.status(200).json({
      success: true,
      distribution
    });
  } catch (error) {
    console.error('Get attack distribution error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get threat timeline
// @route   GET /api/analytics/threat-timeline
// @access  Private
exports.getThreatTimeline = async (req, res) => {
  try {
    const { timeRange = '7d' } = req.query;

    // Get logs grouped by hour/day
    const now = new Date();
    let startDate;
    let groupBy;
    
    switch(timeRange) {
      case '24h':
        startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
        groupBy = 'hour';
        break;
      case '7d':
        startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
        groupBy = 'day';
        break;
      case '30d':
        startDate = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
        groupBy = 'day';
        break;
      default:
        startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
        groupBy = 'day';
    }

    const pipeline = [
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: groupBy === 'hour' ? '%Y-%m-%d %H:00' : '%Y-%m-%d',
              date: '$timestamp'
            }
          },
          critical: {
            $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
          },
          high: {
            $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] }
          },
          medium: {
            $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] }
          },
          total: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ];

    const timelineData = await Log.aggregate(pipeline);

    // Format for chart
    const labels = timelineData.map(item => item._id);
    const datasets = [
      {
        label: 'Critical',
        data: timelineData.map(item => item.critical),
        borderColor: '#dc3545',
        backgroundColor: 'rgba(220, 53, 69, 0.1)',
        tension: 0.4
      },
      {
        label: 'High',
        data: timelineData.map(item => item.high),
        borderColor: '#fd7e14',
        backgroundColor: 'rgba(253, 126, 20, 0.1)',
        tension: 0.4
      },
      {
        label: 'Medium',
        data: timelineData.map(item => item.medium),
        borderColor: '#ffc107',
        backgroundColor: 'rgba(255, 193, 7, 0.1)',
        tension: 0.4
      }
    ];

    res.status(200).json({
      success: true,
      timeline: {
        labels,
        datasets
      }
    });
  } catch (error) {
    console.error('Get threat timeline error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get attack patterns
// @route   GET /api/analytics/patterns
// @access  Private
exports.getPatterns = async (req, res) => {
  try {
    // In a real application, this would use ML algorithms
    // For now, return mock patterns
    
    const patterns = [
      {
        id: 1,
        name: 'Distributed Brute Force',
        confidence: 92,
        description: 'Multiple IP addresses targeting same credentials within 5-minute window',
        type: 'Brute Force',
        frequency: '45 attacks/hour',
        timeframe: 'Last 24 hours',
        severity: 'High'
      },
      {
        id: 2,
        name: 'Port Scan Cascade',
        confidence: 87,
        description: 'Sequential port scanning from same subnet',
        type: 'Port Scan',
        frequency: '120 scans/minute',
        timeframe: 'Last 2 hours',
        severity: 'Medium'
      },
      {
        id: 3,
        name: 'XSS Payload Pattern',
        confidence: 95,
        description: 'Similar XSS payloads across multiple endpoints',
        type: 'XSS',
        frequency: '18 attacks',
        timeframe: 'Last 6 hours',
        severity: 'High'
      }
    ];

    res.status(200).json({
      success: true,
      patterns
    });
  } catch (error) {
    console.error('Get patterns error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get top attackers
// @route   GET /api/analytics/top-attackers
// @access  Private
exports.getTopAttackers = async (req, res) => {
  try {
    const { limit = 10, timeRange = '24h' } = req.query;

    const now = new Date();
    let startDate;
    
    switch(timeRange) {
      case '1h':
        startDate = new Date(now.getTime() - (60 * 60 * 1000));
        break;
      case '24h':
        startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
        break;
      case '7d':
        startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
        break;
      case '30d':
        startDate = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
        break;
      default:
        startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
    }

    const topAttackers = await Log.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$sourceIP',
          count: { $sum: 1 },
          lastSeen: { $max: '$timestamp' },
          attacks: {
            $push: {
              type: '$attackType',
              severity: '$severity',
              timestamp: '$timestamp'
            }
          }
        }
      },
      {
        $project: {
          ip: '$_id',
          count: 1,
          lastSeen: 1,
          topAttackType: {
            $arrayElemAt: [
              {
                $map: {
                  input: {
                    $slice: ['$attacks', 5]
                  },
                  as: 'attack',
                  in: '$$attack.type'
                }
              },
              0
            ]
          },
          severity: {
            $cond: {
              if: {
                $anyElementTrue: {
                  $map: {
                    input: '$attacks',
                    as: 'attack',
                    in: { $eq: ['$$attack.severity', 'critical'] }
                  }
                }
              },
              then: 'critical',
              else: {
                $cond: {
                  if: {
                    $anyElementTrue: {
                      $map: {
                        input: '$attacks',
                        as: 'attack',
                        in: { $eq: ['$$attack.severity', 'high'] }
                      }
                    }
                  },
                  then: 'high',
                  else: 'medium'
                }
              }
            }
          }
        }
      },
      { $sort: { count: -1 } },
      { $limit: parseInt(limit) }
    ]);

    res.status(200).json({
      success: true,
      topAttackers
    });
  } catch (error) {
    console.error('Get top attackers error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get anomalies
// @route   GET /api/analytics/anomalies
// @access  Private
exports.getAnomalies = async (req, res) => {
  try {
    // In a real application, this would use anomaly detection algorithms
    // For now, return mock anomalies based on recent critical logs
    
    const criticalLogs = await Log.find({
      severity: 'critical',
      timestamp: {
        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
      }
    }).limit(5);

    const anomalies = criticalLogs.map((log, index) => ({
      id: index + 1,
      title: `Critical ${log.attackType} Attack`,
      severity: 'Critical',
      description: `Critical ${log.attackType} attack detected from ${log.sourceIP}`,
      timestamp: log.timestamp,
      confidence: 85 + Math.floor(Math.random() * 15),
      relatedLogId: log._id,
      sourceIP: log.sourceIP
    }));

    // Add mock anomalies if no critical logs
    if (anomalies.length === 0) {
      anomalies.push({
        id: 1,
        title: 'Unusual Network Traffic Pattern',
        severity: 'High',
        description: 'Detected unusual spike in outbound traffic',
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
        confidence: 78,
        sourceIP: 'Multiple'
      });
    }

    res.status(200).json({
      success: true,
      anomalies
    });
  } catch (error) {
    console.error('Get anomalies error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get remediation suggestions
// @route   GET /api/analytics/remediations
// @access  Private
exports.getRemediations = async (req, res) => {
  try {
    const { limit = 5 } = req.query;

    // Get recent critical and high severity logs
    const criticalLogs = await Log.find({
      severity: { $in: ['critical', 'high'] },
      timestamp: {
        $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
      }
    }).limit(20);

    // Group by attack type and generate suggestions
    const attackTypeCounts = {};
    criticalLogs.forEach(log => {
      attackTypeCounts[log.attackType] = (attackTypeCounts[log.attackType] || 0) + 1;
    });

    const remediations = Object.entries(attackTypeCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([attackType, count], index) => {
        const suggestions = {
          'XSS': [
            'Implement Content Security Policy (CSP) headers',
            'Validate and sanitize all user inputs',
            'Use output encoding when displaying user data'
          ],
          'SQL Injection': [
            'Use prepared statements and parameterized queries',
            'Implement stored procedures',
            'Apply principle of least privilege to database accounts'
          ],
          'Port Scan': [
            'Configure firewall to block port scanning attempts',
            'Implement intrusion detection systems (IDS)',
            'Use port knocking techniques'
          ],
          'Brute Force': [
            'Implement account lockout policies (3-5 attempts)',
            'Use CAPTCHA after failed login attempts',
            'Enable multi-factor authentication (MFA)'
          ],
          'DDoS': [
            'Use DDoS protection services (Cloudflare, Akamai, AWS Shield)',
            'Implement rate limiting and throttling',
            'Use load balancers to distribute traffic'
          ]
        };

        return {
          id: index + 1,
          title: `Remediate ${attackType} Attacks`,
          priority: count > 10 ? 'Critical' : count > 5 ? 'High' : 'Medium',
          attackType,
          count,
          suggestions: suggestions[attackType] || [
            'Analyze attack pattern and source',
            'Update security rules and policies',
            'Monitor for similar attack patterns'
          ],
          effectiveness: 85 + Math.floor(Math.random() * 15),
          effort: count > 10 ? 'High' : 'Medium'
        };
      });

    res.status(200).json({
      success: true,
      remediations
    });
  } catch (error) {
    console.error('Get remediations error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get predictions
// @route   GET /api/analytics/predictions
// @access  Private
exports.getPredictions = async (req, res) => {
  try {
    // Analyze recent patterns to make predictions
    const recentLogs = await Log.find({
      timestamp: {
        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
      }
    }).limit(100);

    // Simple prediction logic
    const attackTypeCounts = {};
    recentLogs.forEach(log => {
      attackTypeCounts[log.attackType] = (attackTypeCounts[log.attackType] || 0) + 1;
    });

    const predictions = Object.entries(attackTypeCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([attackType, count], index) => {
        const probability = Math.min(95, Math.floor((count / recentLogs.length) * 100) + 30);
        
        const descriptions = {
          'XSS': 'Likely continued XSS attacks targeting web applications',
          'SQL Injection': 'Probable SQL injection attempts on database endpoints',
          'Port Scan': 'Expected port scanning activity from various sources',
          'Brute Force': 'Potential brute force attacks on authentication systems',
          'DDoS': 'Possible DDoS attack based on traffic patterns',
          'Malware': 'Risk of malware distribution through various vectors'
        };

        return {
          id: index + 1,
          title: `${attackType} Attack Probability`,
          probability,
          description: descriptions[attackType] || `Potential ${attackType} attacks detected`,
          timeframe: 'Next 24 hours',
          confidence: 75 + Math.floor(Math.random() * 20),
          recommendations: [
            'Increase monitoring for this attack type',
            'Review and update relevant security controls',
            'Prepare incident response procedures'
          ]
        };
      });

    // Add general prediction if not enough specific ones
    if (predictions.length < 3) {
      predictions.push({
        id: predictions.length + 1,
        title: 'General Attack Activity',
        probability: 65,
        description: 'Continued security threats from various sources expected',
        timeframe: 'Next 48 hours',
        confidence: 70,
        recommendations: [
          'Maintain heightened security posture',
          'Review all security alerts promptly',
          'Ensure backup systems are operational'
        ]
      });
    }

    res.status(200).json({
      success: true,
      predictions
    });
  } catch (error) {
    console.error('Get predictions error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get AI insights
// @route   GET /api/analytics/ai-insights
// @access  Private
exports.getAIInsights = async (req, res) => {
  try {
    // Analyze data from multiple sources
    const [logStats, incidentStats, topAttackers] = await Promise.all([
      Log.getStatistics('7d'),
      Incident.getStatistics(),
      exports.getTopAttackers(req, res).then(response => response.topAttackers)
    ]);

    const insights = [];

    // Insight 1: Attack pattern shift
    if (logStats.attackTypeDistribution) {
      const topAttack = logStats.attackTypeDistribution[0];
      if (topAttack && topAttack.count > 20) {
        insights.push({
          id: 1,
          title: `Dominant Attack Pattern: ${topAttack._id}`,
          confidence: 85,
          content: `${topAttack._id} attacks account for ${Math.round((topAttack.count / logStats.totalLogs[0]?.count || 1) * 100)}% of all attacks in the last 7 days. Consider focusing security measures on this specific threat vector.`,
          recommendations: [
            `Review and update ${topAttack._id} protection mechanisms`,
            'Conduct targeted security training',
            'Implement additional monitoring for this attack type'
          ],
          timestamp: new Date()
        });
      }
    }

    // Insight 2: Response time analysis
    if (incidentStats.avgResponseTime && incidentStats.avgResponseTime[0]?.avg > 120) {
      insights.push({
        id: 2,
        title: 'Incident Response Time Optimization Needed',
        confidence: 78,
        content: `Average incident response time is ${Math.round(incidentStats.avgResponseTime[0].avg)} minutes, exceeding the optimal target of 60 minutes.`,
        recommendations: [
          'Review incident response procedures',
          'Consider automated response systems',
          'Provide additional training to response team'
        ],
        timestamp: new Date(Date.now() - 60 * 60 * 1000)
      });
    }

    // Insight 3: Geographic patterns
    if (topAttackers && topAttackers.length > 0) {
      const topSource = topAttackers[0];
      if (topSource && topSource.count > 50) {
        insights.push({
          id: 3,
          title: 'Concentrated Attack Source',
          confidence: 82,
          content: `IP ${topSource.ip} is responsible for ${topSource.count} attacks, representing a significant portion of total attack volume.`,
          recommendations: [
            'Consider blocking this IP address',
            'Investigate the source for potential threat actor identification',
            'Monitor for similar patterns from related IPs'
          ],
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000)
        });
      }
    }

    // Add general insight if not enough specific ones
    if (insights.length < 3) {
      insights.push({
        id: insights.length + 1,
        title: 'Security Posture Analysis',
        confidence: 75,
        content: 'Overall security posture appears stable with consistent detection rates. Continue monitoring for emerging threats.',
        recommendations: [
          'Maintain current security controls',
          'Regularly update threat intelligence',
          'Conduct periodic security assessments'
        ],
        timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000)
      });
    }

    res.status(200).json({
      success: true,
      insights
    });
  } catch (error) {
    console.error('Get AI insights error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Generate analytics
// @route   POST /api/analytics/generate
// @access  Private
exports.generateAnalytics = async (req, res) => {
  try {
    const analytics = await Analytics.generateDailyAnalytics();

    res.status(200).json({
      success: true,
      analytics
    });
  } catch (error) {
    console.error('Generate analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Export analytics report
// @route   GET /api/analytics/export
// @access  Private
exports.exportAnalytics = async (req, res) => {
  try {
    const { format = 'json', timeRange = '7d' } = req.query;

    // Get comprehensive analytics data
    const [overview, attackDistribution, threatTimeline, patterns, topAttackers, anomalies, remediations, predictions, insights] = await Promise.all([
      exports.getOverview({ query: { timeRange } }, { json: () => {} }),
      exports.getAttackDistribution({ query: { timeRange } }, { json: () => {} }),
      exports.getThreatTimeline({ query: { timeRange } }, { json: () => {} }),
      exports.getPatterns({}, { json: () => {} }),
      exports.getTopAttackers({ query: { timeRange } }, { json: () => {} }),
      exports.getAnomalies({}, { json: () => {} }),
      exports.getRemediations({}, { json: () => {} }),
      exports.getPredictions({}, { json: () => {} }),
      exports.getAIInsights({}, { json: () => {} })
    ]);

    const report = {
      timestamp: new Date().toISOString(),
      timeRange,
      overview: overview.analytics,
      attackDistribution: attackDistribution.distribution,
      threatTimeline: threatTimeline.timeline,
      patterns: patterns.patterns,
      topAttackers: topAttackers.topAttackers,
      anomalies: anomalies.anomalies,
      remediations: remediations.remediations,
      predictions: predictions.predictions,
      insights: insights.insights,
      summary: {
        threatLevel: overview.analytics?.threatLevel || 'medium',
        totalLogs: overview.analytics?.metrics?.totalLogs || 0,
        criticalIncidents: overview.analytics?.incidentStats?.openCritical?.[0]?.count || 0,
        detectionRate: overview.analytics?.metrics?.detectionRate || 0
      }
    };

    if (format === 'csv') {
      // Convert to CSV (simplified version)
      let csv = 'MicroSOC Analytics Report\n\n';
      csv += `Generated: ${report.timestamp}\n`;
      csv += `Time Range: ${timeRange}\n\n`;
      
      csv += 'Summary:\n';
      csv += `Threat Level,${report.summary.threatLevel}\n`;
      csv += `Total Logs,${report.summary.totalLogs}\n`;
      csv += `Critical Incidents,${report.summary.criticalIncidents}\n`;
      csv += `Detection Rate,${report.summary.detectionRate}%\n\n`;

      csv += 'Top Attackers:\n';
      csv += 'IP,Count,Last Seen,Top Attack Type\n';
      report.topAttackers.forEach(attacker => {
        csv += `${attacker.ip},${attacker.count},${attacker.lastSeen},${attacker.topAttackType}\n`;
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=analytics-report-${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csv);
    } else {
      // Return as JSON
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=analytics-report-${new Date().toISOString().split('T')[0]}.json`);
      res.send(JSON.stringify(report, null, 2));
    }
  } catch (error) {
    console.error('Export analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};