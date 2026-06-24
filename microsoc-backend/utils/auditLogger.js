const AuditLog = require('../models/AuditLog');

function pickActor(req) {
  const user = req?.user || {};
  return {
    actor: user.id,
    actorName: user.name || 'System',
    actorEmail: user.email || 'system@microsoc.local',
    actorRole: user.role || 'system'
  };
}

async function recordAuditEvent(req, event = {}) {
  try {
    const hasReqUser = Boolean(req && req.user);
    const actor = hasReqUser ? pickActor(req) : {
      actor: event.actor || null,
      actorName: event.actorName || 'System',
      actorEmail: event.actorEmail || 'system@microsoc.local',
      actorRole: event.actorRole || 'system'
    };

    const payload = {
      ...actor,
      action: event.action || 'Unknown Action',
      module: event.module || 'general',
      targetType: event.targetType || '',
      targetId: event.targetId || '',
      targetLabel: event.targetLabel || '',
      result: event.result || 'success',
      details: event.details || event.action || 'Audit event recorded',
      ipAddress: hasReqUser ? (req.ip || req.headers?.['x-forwarded-for'] || 'Unknown') : (event.ipAddress || 'Unknown'),
      userAgent: hasReqUser ? (req.headers?.['user-agent'] || 'Unknown') : (event.userAgent || 'Unknown'),
      metadata: event.metadata || {}
    };

    await AuditLog.create(payload);
    return payload;
  } catch (error) {
    console.error('Audit log write failed:', error.message);
    return null;
  }
}

module.exports = {
  recordAuditEvent
};
