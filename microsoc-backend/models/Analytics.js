const mongoose = require('mongoose');

const AnalyticsSchema = new mongoose.Schema({
  date: {
    type: Date,
    required: true,
    index: true
  },
  metrics: {
    totalLogs: {
      type: Number,
      default: 0
    },
    blockedAttacks: {
      type: Number,
      default: 0
    },
    criticalLogs: {
      type: Number,
      default: 0
    },
    avgResponseTime: {
      type: Number,
      default: 0
    },
    attackSuccessRate: {
      type: Number,
      default: 0
    },
    detectionRate: {
      type: Number,
      default: 0
    }
  },
  attackDistribution: {
    xss: { type: Number, default: 0 },
    sqlInjection: { type: Number, default: 0 },
    portScan: { type: Number, default: 0 },
    bruteForce: { type: Number, default: 0 },
    ddos: { type: Number, default: 0 },
    malware: { type: Number, default: 0 },
    phishing: { type: Number, default: 0 },
    other: { type: Number, default: 0 }
  },
  threatLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  topAttackers: [{
    ip: String,
    count: Number,
    country: String
  }],
  patterns: [{
    name: String,
    type: String,
    confidence: Number,
    description: String,
    severity: String,
    frequency: String
  }],
  anomalies: [{
    type: String,
    description: String,
    severity: String,
    timestamp: Date,
    confidence: Number
  }],
  predictions: [{
    title: String,
    probability: Number,
    description: String,
    timeframe: String,
    confidence: Number
  }],
  generatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes
AnalyticsSchema.index({ date: -1 });

// Static method to generate daily analytics
AnalyticsSchema.statics.generateDailyAnalytics = async function(date = new Date()) {
  const startOfDay = new Date(date.setHours(0, 0, 0, 0));
  const endOfDay = new Date(date.setHours(23, 59, 59, 999));
  
  const Log = mongoose.model('Log');
  const Incident = mongoose.model('Incident');
  
  // Get logs for the day
  const logs = await Log.find({
    timestamp: {
      $gte: startOfDay,
      $lte: endOfDay
    }
  });
  
  // Get incidents for the day
  const incidents = await Incident.find({
    createdAt: {
      $gte: startOfDay,
      $lte: endOfDay
    }
  });
  
  // Calculate metrics
  const totalLogs = logs.length;
  const blockedAttacks = logs.filter(log => log.isBlocked).length;
  const criticalLogs = logs.filter(log => log.severity === 'critical').length;
  
  // Calculate attack distribution
  const attackDistribution = {
    xss: 0,
    sqlInjection: 0,
    portScan: 0,
    bruteForce: 0,
    ddos: 0,
    malware: 0,
    phishing: 0,
    other: 0
  };
  
  logs.forEach(log => {
    const attackType = log.attackType.toLowerCase();
    if (attackDistribution.hasOwnProperty(attackType)) {
      attackDistribution[attackType]++;
    } else {
      attackDistribution.other++;
    }
  });
  
  // Calculate threat level based on logs
  let threatLevel = 'low';
  if (criticalLogs > 10) {
    threatLevel = 'critical';
  } else if (criticalLogs > 5) {
    threatLevel = 'high';
  } else if (criticalLogs > 2) {
    threatLevel = 'medium';
  }
  
  // Generate top attackers
  const ipCounts = {};
  logs.forEach(log => {
    if (log.sourceIP) {
      ipCounts[log.sourceIP] = (ipCounts[log.sourceIP] || 0) + 1;
    }
  });
  
  const topAttackers = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({
      ip,
      count,
      country: 'Unknown'
    }));
  
  // Generate mock patterns
  const patterns = [
    {
      name: 'Distributed Attack Pattern',
      type: 'Behavioral',
      confidence: 85 + Math.floor(Math.random() * 15),
      description: 'Multiple coordinated attacks detected',
      severity: 'high',
      frequency: `${Math.floor(Math.random() * 50) + 10} attacks/hour`
    }
  ];
  
  // Generate mock anomalies
  const anomalies = criticalLogs > 0 ? [
    {
      type: 'Unusual Activity',
      description: 'Critical attacks detected',
      severity: 'high',
      timestamp: new Date(),
      confidence: 90
    }
  ] : [];
  
  // Create analytics record
  const analytics = new this({
    date: startOfDay,
    metrics: {
      totalLogs,
      blockedAttacks,
      criticalLogs,
      avgResponseTime: Math.floor(Math.random() * 5) + 1, // Mock data
      attackSuccessRate: Math.floor((blockedAttacks / totalLogs) * 100) || 0,
      detectionRate: 95 + Math.floor(Math.random() * 5) // Mock data
    },
    attackDistribution,
    threatLevel,
    topAttackers,
    patterns,
    anomalies
  });
  
  await analytics.save();
  return analytics;
};

module.exports = mongoose.model('Analytics', AnalyticsSchema);