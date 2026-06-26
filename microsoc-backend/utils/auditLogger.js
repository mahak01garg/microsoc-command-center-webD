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

function pickRequestIp(req) {
  const forwardedFor = req?.headers?.['x-forwarded-for'];
  const realIp = req?.headers?.['x-real-ip'];
  const forwardedValue = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
  const firstForwardedIp = forwardedValue ? String(forwardedValue).split(',')[0].trim() : '';

  return firstForwardedIp || realIp || req?.ip || req?.socket?.remoteAddress || '';
}

async function recordAuditEvent(req, event = {}) {
  try {
    const forceSystemActor = Boolean(event.systemAction);
    const hasReqUser = Boolean(req && req.user && !forceSystemActor);
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
      ipAddress: hasReqUser ? pickRequestIp(req) : (event.ipAddress || ''),
      userAgent: hasReqUser ? (req.headers?.['user-agent'] || '') : (event.userAgent || ''),
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
  recordAuditEvent,
  pickRequestIp
};
