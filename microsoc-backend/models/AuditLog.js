const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  actor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  actorName: {
    type: String,
    required: true,
    trim: true
  },
  actorEmail: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  actorRole: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  action: {
    type: String,
    required: true,
    trim: true
  },
  module: {
    type: String,
    required: true,
    trim: true
  },
  targetType: {
    type: String,
    trim: true
  },
  targetId: {
    type: String,
    trim: true
  },
  targetLabel: {
    type: String,
    trim: true
  },
  result: {
    type: String,
    enum: ['success', 'failure', 'warning'],
    default: 'success'
  },
  details: {
    type: String,
    required: true,
    trim: true
  },
  ipAddress: {
    type: String,
    default: 'Unknown'
  },
  userAgent: {
    type: String,
    default: 'Unknown'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, {
  timestamps: true
});

AuditLogSchema.index({ module: 1, timestamp: -1 });
AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ actor: 1, timestamp: -1 });
AuditLogSchema.index({ result: 1, timestamp: -1 });

AuditLogSchema.statics.getStatistics = async function(timeRange = '24h') {
  const now = new Date();
  let startDate;

  switch (timeRange) {
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
    case 'all':
      startDate = null;
      break;
    default:
      startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
  }

  const pipeline = [];
  if (startDate) {
    pipeline.push({ $match: { timestamp: { $gte: startDate } } });
  }
  pipeline.push({
    $facet: {
      totalEvents: [{ $count: 'count' }],
      byModule: [{ $group: { _id: '$module', count: { $sum: 1 } } }, { $sort: { count: -1 } }],
      byAction: [{ $group: { _id: '$action', count: { $sum: 1 } } }, { $sort: { count: -1 } }],
      byResult: [{ $group: { _id: '$result', count: { $sum: 1 } } }],
      byRole: [{ $group: { _id: '$actorRole', count: { $sum: 1 } } }],
      hourlyTrend: [
        { $group: { _id: { hour: { $hour: '$timestamp' }, day: { $dayOfMonth: '$timestamp' } }, count: { $sum: 1 } } },
        { $sort: { '_id.day': 1, '_id.hour': 1 } }
      ]
    }
  });

  const stats = await this.aggregate(pipeline);

  return stats[0] || {};
};

module.exports = mongoose.model('AuditLog', AuditLogSchema);
