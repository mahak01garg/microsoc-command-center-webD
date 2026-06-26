const SystemSettings = require('../models/SystemSettings');
const { recordAuditEvent } = require('../utils/auditLogger');

const DEFAULT_SETTINGS = {
  generalSettings: {
    theme: 'dark',
    autoRefreshEnabled: true,
    refreshIntervalSeconds: 30
  },
  alertConfig: {
    failedLoginThreshold: 5,
    otherAlertsThreshold: 1
  },
  incidentConfig: {
    createIncidentAfter: 3,
    severityEscalationEnabled: true
  },
  aiSettings: {
    analysisEnabled: true,
    autoGenerateRecommendations: true
  },
  notificationSettings: {
    emailNotifications: true,
    criticalAlertNotifications: true,
    incidentAssignmentNotifications: true
  }
};

function normalizeSettings(settings) {
  const source = settings?.toObject ? settings.toObject() : (settings || {});
  return {
    id: source._id || source.id,
    key: source.key || 'global',
    generalSettings: {
      ...DEFAULT_SETTINGS.generalSettings,
      ...(source.generalSettings || {}),
      theme: String(source.generalSettings?.theme || DEFAULT_SETTINGS.generalSettings.theme).toLowerCase() === 'light' ? 'light' : 'dark'
    },
    alertConfig: {
      failedLoginThreshold: coerceNumber(source.alertConfig?.failedLoginThreshold, DEFAULT_SETTINGS.alertConfig.failedLoginThreshold, 1, 100),
      otherAlertsThreshold: coerceNumber(source.alertConfig?.otherAlertsThreshold, DEFAULT_SETTINGS.alertConfig.otherAlertsThreshold, 1, 1000)
    },
    incidentConfig: {
      ...DEFAULT_SETTINGS.incidentConfig,
      ...(source.incidentConfig || {})
    },
    aiSettings: {
      ...DEFAULT_SETTINGS.aiSettings,
      ...(source.aiSettings || {})
    },
    notificationSettings: {
      ...DEFAULT_SETTINGS.notificationSettings,
      ...(source.notificationSettings || {})
    },
    updatedBy: source.updatedBy,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt
  };
}

function coerceNumber(value, fallback, min = -Infinity, max = Infinity) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function coerceBoolean(value, fallback) {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return fallback;
}

function applyIncomingSettings(target, incoming = {}) {
  if (incoming.generalSettings) {
    target.set('generalSettings.theme', String(incoming.generalSettings.theme || target.generalSettings.theme).toLowerCase() === 'light' ? 'light' : 'dark');
    target.set('generalSettings.autoRefreshEnabled', coerceBoolean(incoming.generalSettings.autoRefreshEnabled, target.generalSettings.autoRefreshEnabled));
    target.set('generalSettings.refreshIntervalSeconds', coerceNumber(incoming.generalSettings.refreshIntervalSeconds, target.generalSettings.refreshIntervalSeconds, 5, 300));
  }

  if (incoming.alertConfig) {
    target.set('alertConfig.failedLoginThreshold', coerceNumber(incoming.alertConfig.failedLoginThreshold, target.alertConfig.failedLoginThreshold, 1, 100));
    target.set('alertConfig.otherAlertsThreshold', coerceNumber(incoming.alertConfig.otherAlertsThreshold, target.alertConfig.otherAlertsThreshold, 1, 1000));
  }

  if (incoming.incidentConfig) {
    target.set('incidentConfig.createIncidentAfter', coerceNumber(incoming.incidentConfig.createIncidentAfter, target.incidentConfig.createIncidentAfter, 1, 20));
    target.set('incidentConfig.severityEscalationEnabled', coerceBoolean(incoming.incidentConfig.severityEscalationEnabled, target.incidentConfig.severityEscalationEnabled));
  }

  if (incoming.aiSettings) {
    target.set('aiSettings.analysisEnabled', coerceBoolean(incoming.aiSettings.analysisEnabled, target.aiSettings.analysisEnabled));
    target.set('aiSettings.autoGenerateRecommendations', coerceBoolean(incoming.aiSettings.autoGenerateRecommendations, target.aiSettings.autoGenerateRecommendations));
  }

  if (incoming.notificationSettings) {
    target.set('notificationSettings.emailNotifications', coerceBoolean(incoming.notificationSettings.emailNotifications, target.notificationSettings.emailNotifications));
    target.set('notificationSettings.criticalAlertNotifications', coerceBoolean(incoming.notificationSettings.criticalAlertNotifications, target.notificationSettings.criticalAlertNotifications));
    target.set('notificationSettings.incidentAssignmentNotifications', coerceBoolean(incoming.notificationSettings.incidentAssignmentNotifications, target.notificationSettings.incidentAssignmentNotifications));
  }
}

exports.getSettings = async (req, res) => {
  try {
    const settings = await SystemSettings.getSingleton();
    res.status(200).json({
      success: true,
      settings: normalizeSettings(settings)
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.updateSettings = async (req, res) => {
  try {
    const settings = await SystemSettings.getSingleton();
    const before = normalizeSettings(settings);
    applyIncomingSettings(settings, req.body || {});
    [
      'generalSettings',
      'alertConfig',
      'incidentConfig',
      'aiSettings',
      'notificationSettings'
    ].forEach(path => settings.markModified(path));
    settings.updatedBy = req.user?.email || req.user?.name || 'admin';
    await settings.save();

    try {
      await recordAuditEvent(req, {
        systemAction: true,
        action: 'Settings Updated',
        module: 'settings',
        targetType: 'SystemSettings',
        targetId: String(settings._id),
        targetLabel: 'Global SOC Settings',
        details: 'System settings changed through admin controls',
        metadata: {
          changedBy: req.user?.email || req.user?.name || 'admin',
          previous: before,
          next: normalizeSettings(settings)
        }
      });
    } catch (auditError) {
      console.warn('Settings audit log failed:', auditError.message);
    }

    res.status(200).json({
      success: true,
      settings: normalizeSettings(settings)
    });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Server error'
    });
  }
};
