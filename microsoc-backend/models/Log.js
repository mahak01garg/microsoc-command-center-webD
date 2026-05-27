const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  attackType: {
    type: String,
    required: true,
    enum: [
      'XSS',
      'SQL Injection', 
      'Port Scan',
      'Brute Force',
      'DDoS',
      'Malware',
      'Phishing',
      'Insider Threat',
      'Ransomware',
      'Zero-Day',
      'MITM',
      'Credential Theft',
      'Data Exfiltration',
      'IoT Attack',
      'Supply Chain',
      'Other'
    ]
  },
  sourceIP: {
    type: String,
    required: true,
    match: [
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
      'Please provide a valid IP address'
    ]
  },
  targetSystem: {
    type: String,
    required: true,
    maxlength: [100, 'Target system cannot be more than 100 characters']
  },
  severity: {
    type: String,
    required: true,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'medium'
  },
  country: {
    type: String,
    default: 'Unknown',
    maxlength: [50, 'Country cannot be more than 50 characters']
  },
  description: {
    type: String,
    required: true,
    maxlength: [500, 'Description cannot be more than 500 characters']
  },
  isBlocked: {
    type: Boolean,
    default: false
  },
  userAgent: {
    type: String,
    maxlength: [500, 'User agent cannot be more than 500 characters']
  },
  port: {
    type: Number,
    min: 1,
    max: 65535
  },
  protocol: {
    type: String,
    enum: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'Other']
  },
  metadata: {
    requestSize: Number,
    responseCode: Number,
    duration: Number,
    headers: mongoose.Schema.Types.Mixed
  },
  tags: [{
    type: String,
    maxlength: [50, 'Tag cannot be more than 50 characters']
  }],
  source: {
    type: String,
    enum: ['firewall', 'ids', 'waf', 'antivirus', 'manual', 'api', 'other'],
    default: 'ids'
  },
  processedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  processedAt: Date,
  notes: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    note: String,
    timestamp: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

// Indexes for faster queries
LogSchema.index({ timestamp: -1 });
LogSchema.index({ attackType: 1 });
LogSchema.index({ severity: 1 });
LogSchema.index({ sourceIP: 1 });
LogSchema.index({ isBlocked: 1 });
LogSchema.index({ 'tags': 1 });

// Static method to get log statistics
LogSchema.statics.getStatistics = async function(timeRange = '24h') {
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
  
  const stats = await this.aggregate([
    {
      $match: {
        timestamp: { $gte: startDate }
      }
    },
    {
      $facet: {
        totalLogs: [{ $count: 'count' }],
        severityDistribution: [
          { $group: { _id: '$severity', count: { $sum: 1 } } }
        ],
        attackTypeDistribution: [
          { $group: { _id: '$attackType', count: { $sum: 1 } } }
        ],
        blockedAttacks: [
          { $match: { isBlocked: true } },
          { $count: 'count' }
        ],
        topAttackers: [
          { $group: { _id: '$sourceIP', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ],
        hourlyTrend: [
          {
            $group: {
              _id: {
                hour: { $hour: '$timestamp' },
                day: { $dayOfMonth: '$timestamp' }
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { '_id.day': 1, '_id.hour': 1 } }
        ]
      }
    }
  ]);
  
  return stats[0];
};

// Method to generate mock log
LogSchema.statics.generateMockLog = function() {
  const attackTypes = ['XSS', 'SQL Injection', 'Port Scan', 'Brute Force', 'DDoS', 'Malware', 'Phishing'];
  const severities = ['critical', 'high', 'medium', 'low'];
  const countries = ['US', 'CN', 'RU', 'DE', 'IN', 'BR', 'JP', 'KR', 'UK'];
  const targetSystems = ['web-server-01', 'db-server-01', 'auth-server-01', 'api-gateway', 'firewall-01'];
  
  return {
    attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
    sourceIP: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    targetSystem: targetSystems[Math.floor(Math.random() * targetSystems.length)],
    severity: severities[Math.floor(Math.random() * severities.length)],
    country: countries[Math.floor(Math.random() * countries.length)],
    description: `Mock ${attackTypes[Math.floor(Math.random() * attackTypes.length)]} attack detected`,
    isBlocked: Math.random() > 0.3,
    port: Math.floor(Math.random() * 65535),
    protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
    userAgent: `Mock Agent ${Math.floor(Math.random() * 1000)}`
  };
};

module.exports = mongoose.model('Log', LogSchema);