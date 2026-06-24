const mongoose = require('mongoose');

const SystemSettingsSchema = new mongoose.Schema({
  key: {
    type: String,
    default: 'global',
    unique: true,
    index: true
  },
  generalSettings: {
    theme: { type: String, enum: ['dark', 'light'], default: 'dark' },
    autoRefreshEnabled: { type: Boolean, default: true },
    refreshIntervalSeconds: { type: Number, default: 30, min: 5, max: 300 }
  },
  alertConfig: {
    failedLoginThreshold: { type: Number, default: 5, min: 1, max: 100 },
    portScanThreshold: { type: Number, default: 10, min: 1, max: 1000 },
    ddosThreshold: { type: Number, default: 1000, min: 10, max: 100000 }
  },
  incidentConfig: {
    createIncidentAfter: { type: Number, default: 3, min: 1, max: 20 },
    severityEscalationEnabled: { type: Boolean, default: true }
  },
  aiSettings: {
    analysisEnabled: { type: Boolean, default: true },
    autoGenerateRecommendations: { type: Boolean, default: true }
  },
  notificationSettings: {
    emailNotifications: { type: Boolean, default: true },
    criticalAlertNotifications: { type: Boolean, default: true },
    incidentAssignmentNotifications: { type: Boolean, default: true }
  },
  updatedBy: {
    type: String,
    default: 'system'
  }
}, {
  timestamps: true
});

SystemSettingsSchema.statics.getSingleton = async function () {
  let settings = await this.findOne({ key: 'global' });
  if (!settings) {
    settings = await this.create({ key: 'global' });
  }
  return settings;
};

module.exports = mongoose.model('SystemSettings', SystemSettingsSchema);
