const mongoose = require('mongoose');

const IncidentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Please provide an incident title'],
    trim: true,
    maxlength: [200, 'Title cannot be more than 200 characters']
  },
  description: {
    type: String,
    required: [true, 'Please provide an incident description'],
    maxlength: [2000, 'Description cannot be more than 2000 characters']
  },
  severity: {
    type: String,
    required: true,
    enum: ['critical', 'high', 'medium', 'low'],
    default: 'medium'
  },
  status: {
    type: String,
    enum: ['open', 'in_progress', 'resolved', 'closed'],
    default: 'open'
  },
  category: {
    type: String,
    enum: [
      'malware',
      'phishing', 
      'ddos',
      'insider_threat',
      'data_breach',
      'vulnerability',
      'configuration_error',
      'other'
    ],
    default: 'other'
  },
  sourceIP: {
    type: String,
    match: [
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
      'Please provide a valid IP address'
    ]
  },
  affectedSystems: [{
    type: String,
    maxlength: [100, 'System name cannot be more than 100 characters']
  }],
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  relatedLogs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Log'
  }],
  impact: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  sla: {
    responseTime: Number, // in minutes
    resolutionTime: Number, // in minutes
    responseDeadline: Date,
    resolutionDeadline: Date,
    isBreached: {
      type: Boolean,
      default: false
    }
  },
  timeline: [{
    action: String,
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    note: String,
    attachments: [{
      filename: String,
      url: String,
      uploadedAt: Date
    }]
  }],
  remediationSteps: [{
    step: String,
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    status: {
      type: String,
      enum: ['pending', 'in_progress', 'completed', 'failed'],
      default: 'pending'
    },
    deadline: Date,
    completedAt: Date,
    notes: String
  }],
  rootCause: {
    type: String,
    maxlength: [500, 'Root cause cannot be more than 500 characters']
  },
  lessonsLearned: {
    type: String,
    maxlength: [1000, 'Lessons learned cannot be more than 1000 characters']
  },
  isFalsePositive: {
    type: Boolean,
    default: false
  },
  tags: [{
    type: String,
    maxlength: [50, 'Tag cannot be more than 50 characters']
  }],
  closedAt: Date,
  closedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  metrics: {
    timeToDetect: Number, // in minutes
    timeToRespond: Number, // in minutes
    timeToResolve: Number, // in minutes
    costImpact: Number, // in currency
    businessImpact: String
  }
}, {
  timestamps: true
});

// Indexes
IncidentSchema.index({ status: 1 });
IncidentSchema.index({ severity: 1 });
IncidentSchema.index({ assignedTo: 1 });
IncidentSchema.index({ createdBy: 1 });
IncidentSchema.index({ createdAt: -1 });

// Pre-save middleware to update SLA deadlines
IncidentSchema.pre('save', function(next) {
  if (this.isNew && !this.sla.responseDeadline) {
    const responseTime = this.sla.responseTime || 60; // Default 60 minutes
    this.sla.responseDeadline = new Date(Date.now() + responseTime * 60000);
  }
  next();
});

// Method to add timeline event
IncidentSchema.methods.addTimelineEvent = function(action, user, note, attachments = []) {
  this.timeline.push({
    action,
    user,
    note,
    attachments,
    timestamp: new Date()
  });
  return this.save();
};

// Method to update status with timeline event
IncidentSchema.methods.updateStatus = async function(newStatus, user, note) {
  const oldStatus = this.status;
  this.status = newStatus;
  
  // Update timeline
  await this.addTimelineEvent(
    `Status changed from ${oldStatus} to ${newStatus}`,
    user,
    note
  );
  
  // If closing incident, set closedAt
  if (newStatus === 'closed' && !this.closedAt) {
    this.closedAt = new Date();
    this.closedBy = user;
  }
  
  return this.save();
};

// Static method to get incident statistics
IncidentSchema.statics.getStatistics = async function() {
  const stats = await this.aggregate([
    {
      $facet: {
        statusCounts: [
          { $group: { _id: '$status', count: { $sum: 1 } } }
        ],
        severityCounts: [
          { $group: { _id: '$severity', count: { $sum: 1 } } }
        ],
        openCritical: [
          { 
            $match: { 
              status: 'open',
              severity: 'critical'
            }
          },
          { $count: 'count' }
        ],
        avgResponseTime: [
          { 
            $match: { 
              'metrics.timeToRespond': { $exists: true }
            }
          },
          {
            $group: {
              _id: null,
              avg: { $avg: '$metrics.timeToRespond' }
            }
          }
        ],
        monthlyTrend: [
          {
            $group: {
              _id: {
                year: { $year: '$createdAt' },
                month: { $month: '$createdAt' }
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { '_id.year': 1, '_id.month': 1 } },
          { $limit: 12 }
        ]
      }
    }
  ]);
  
  return stats[0];
};

module.exports = mongoose.model('Incident', IncidentSchema);