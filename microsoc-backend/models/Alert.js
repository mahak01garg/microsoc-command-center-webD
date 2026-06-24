const mongoose = require('mongoose');

const AlertSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Please provide an alert title'],
    trim: true,
    maxlength: [200, 'Alert title cannot be more than 200 characters']
  },
  description: {
    type: String,
    required: [true, 'Please provide an alert description'],
    maxlength: [2500, 'Alert description cannot be more than 2500 characters']
  },
  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'medium',
    index: true
  },
  status: {
    type: String,
    enum: ['new', 'in_progress', 'resolved', 'closed'],
    default: 'new',
    index: true
  },
  sourceIP: {
    type: String,
    index: true
  },
  targetSystem: {
    type: String,
    index: true
  },
  attackType: {
    type: String,
    index: true
  },
  mitreTechnique: {
    type: String,
    default: 'Unknown'
  },
  ruleId: {
    type: String,
    index: true
  },
  correlationKey: {
    type: String,
    index: true,
    unique: false
  },
  evidence: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  log: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Log'
  },
  incident: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Incident'
  },
  occurrenceCount: {
    type: Number,
    default: 1,
    min: 1
  },
  firstSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastSeen: {
    type: Date,
    default: Date.now,
    index: true
  },
  reviewedAt: Date,
  reviewedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  notes: [{
    text: String,
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  deletedAt: Date,
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  deleteReason: {
    type: String,
    maxlength: [500, 'Delete reason cannot be more than 500 characters']
  },
  tags: [{
    type: String,
    maxlength: [50, 'Tag cannot be more than 50 characters']
  }]
}, {
  timestamps: true
});

AlertSchema.index({ lastSeen: -1 });
AlertSchema.index({ deletedAt: 1, lastSeen: -1 });
AlertSchema.index({ severity: 1, status: 1 });

AlertSchema.pre('save', function(next) {
  if (this.isNew && !this.firstSeen) {
    this.firstSeen = new Date();
  }
  this.lastSeen = new Date();
  next();
});

AlertSchema.methods.addNote = function(text, user) {
  this.notes.push({
    text,
    user,
    createdAt: new Date()
  });
  return this.save();
};

AlertSchema.methods.updateStatus = async function(status, user, note) {
  const oldStatus = this.status;
  this.status = status;
  if (note) {
    await this.addNote(`Status changed from ${oldStatus} to ${status}: ${note}`, user);
  }
  if (['resolved', 'closed'].includes(status)) {
    this.reviewedAt = new Date();
    this.reviewedBy = user;
  }
  return this.save();
};

AlertSchema.methods.softDelete = function(user, reason) {
  this.deletedAt = new Date();
  this.deletedBy = user;
  this.deleteReason = reason || 'Removed from active queue';
  return this.save();
};

AlertSchema.statics.getStatistics = async function(timeRange = '24h') {
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
    default:
      startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
  }

  const match = {
    deletedAt: { $exists: false }
  };

  if (startDate) {
    match.lastSeen = { $gte: startDate };
  }

  const stats = await this.aggregate([
    { $match: match },
    {
      $facet: {
        totalAlerts: [{ $count: 'count' }],
        statusCounts: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
        severityCounts: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
        requiringAction: [
          { $match: { status: { $in: ['new', 'in_progress'] } } },
          { $count: 'count' }
        ],
        topSources: [
          { $group: { _id: '$sourceIP', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ],
        attackTypeCounts: [{ $group: { _id: '$attackType', count: { $sum: 1 } } }]
      }
    }
  ]);

  return stats[0];
};

module.exports = mongoose.model('Alert', AlertSchema);
