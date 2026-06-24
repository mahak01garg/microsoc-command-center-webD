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
    portScanThreshold: 10,
    ddosThreshold: 1000
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
      ...DEFAULT_SETTINGS.alertConfig,
      ...(source.alertConfig || {})
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

function coerceNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function coerceBoolean(value, fallback) {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return fallback;
}

function applyIncomingSettings(target, incoming = {}) {
  if (incoming.generalSettings) {
    target.generalSettings = {
      ...target.generalSettings,
      ...incoming.generalSettings,
      theme: String(incoming.generalSettings.theme || target.generalSettings.theme).toLowerCase() === 'light' ? 'light' : 'dark',
      autoRefreshEnabled: coerceBoolean(incoming.generalSettings.autoRefreshEnabled, target.generalSettings.autoRefreshEnabled),
      refreshIntervalSeconds: coerceNumber(incoming.generalSettings.refreshIntervalSeconds, target.generalSettings.refreshIntervalSeconds)
    };
  }

  if (incoming.alertConfig) {
    target.alertConfig = {
      ...target.alertConfig,
      failedLoginThreshold: coerceNumber(incoming.alertConfig.failedLoginThreshold, target.alertConfig.failedLoginThreshold),
      portScanThreshold: coerceNumber(incoming.alertConfig.portScanThreshold, target.alertConfig.portScanThreshold),
      ddosThreshold: coerceNumber(incoming.alertConfig.ddosThreshold, target.alertConfig.ddosThreshold)
    };
  }

  if (incoming.incidentConfig) {
    target.incidentConfig = {
      ...target.incidentConfig,
      createIncidentAfter: coerceNumber(incoming.incidentConfig.createIncidentAfter, target.incidentConfig.createIncidentAfter),
      severityEscalationEnabled: coerceBoolean(incoming.incidentConfig.severityEscalationEnabled, target.incidentConfig.severityEscalationEnabled)
    };
  }

  if (incoming.aiSettings) {
    target.aiSettings = {
      ...target.aiSettings,
      analysisEnabled: coerceBoolean(incoming.aiSettings.analysisEnabled, target.aiSettings.analysisEnabled),
      autoGenerateRecommendations: coerceBoolean(incoming.aiSettings.autoGenerateRecommendations, target.aiSettings.autoGenerateRecommendations)
    };
  }

  if (incoming.notificationSettings) {
    target.notificationSettings = {
      ...target.notificationSettings,
      emailNotifications: coerceBoolean(incoming.notificationSettings.emailNotifications, target.notificationSettings.emailNotifications),
      criticalAlertNotifications: coerceBoolean(incoming.notificationSettings.criticalAlertNotifications, target.notificationSettings.criticalAlertNotifications),
      incidentAssignmentNotifications: coerceBoolean(incoming.notificationSettings.incidentAssignmentNotifications, target.notificationSettings.incidentAssignmentNotifications)
    };
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

    await recordAuditEvent(req, {
      action: 'Settings Updated',
      module: 'settings',
      targetType: 'SystemSettings',
      targetId: String(settings._id),
      targetLabel: 'Global SOC Settings',
      details: 'Admin updated general, alert, incident, AI, or notification settings',
      metadata: {
        previous: before,
        next: normalizeSettings(settings)
      }
    });

    res.status(200).json({
      success: true,
      settings: normalizeSettings(settings)
    });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
