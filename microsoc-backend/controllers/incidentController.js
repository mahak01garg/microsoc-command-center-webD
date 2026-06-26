const Incident = require('../models/Incident');
const Log = require('../models/Log');
const User = require('../models/User');
const SystemSettings = require('../models/SystemSettings');
const { recordAuditEvent } = require('../utils/auditLogger');
const { sendIncidentAssignmentEmail } = require('../utils/approvalMailer');

function canAccessIncident(incident, user) {
  if (!incident || !user) return false;
  if (user.role === 'admin') return true;
  const assignedToId = incident.assignedTo?._id || incident.assignedTo?.id || incident.assignedTo;
  const createdById = incident.createdBy?._id || incident.createdBy?.id || incident.createdBy;
  return String(assignedToId || '') === String(user.id) || String(createdById || '') === String(user.id);
}

function isSystemGeneratedIncident(incident = {}) {
  const tags = Array.isArray(incident.tags) ? incident.tags.map(tag => String(tag).toLowerCase()) : [];
  const source = String(incident.metadata?.source || '').toLowerCase();
  return Boolean(incident.systemGenerated)
    || Boolean(incident.metadata?.systemGenerated)
    || tags.includes('auto-alert-correlation')
    || tags.includes('frontend-fallback')
    || source.includes('auto')
    || source.includes('system');
}

// @desc    Get all incidents
// @route   GET /api/incidents
// @access  Private
exports.getIncidents = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      status,
      severity,
      assignedTo,
      search,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;

    // Build query
    const query = {
      archived: { $ne: true }
    };

    if (req.user.role !== 'admin') {
      query.$or = [
        { assignedTo: req.user.id },
        { createdBy: req.user.id }
      ];
    }

    // Status filter
    if (status && status !== 'all') {
      query.status = status;
    }

    // Severity filter
    if (severity && severity !== 'all') {
      query.severity = severity;
    }

    // Assigned to filter
    if (assignedTo) {
      if (assignedTo === 'unassigned') {
        query.assignedTo = null;
      } else if (assignedTo === 'me') {
        query.assignedTo = req.user.id;
      } else {
        query.assignedTo = assignedTo;
      }
    }

    // Search filter
    if (search) {
      const searchClause = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { sourceIP: { $regex: search, $options: 'i' } }
      ];
      query.$and = query.$and || [];
      query.$and.push({ $or: searchClause });
    }

    // Sort
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    // Execute query with pagination
    const incidents = await Incident.find(query)
      .populate('assignedTo', 'name email avatar')
      .populate('createdBy', 'name email')
      .populate('relatedLogs', 'timestamp attackType sourceIP severity')
      .sort(sort)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Incident.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get statistics
    const stats = await Incident.getStatistics();

    res.status(200).json({
      success: true,
      count: incidents.length,
      total,
      page: parseInt(page),
      totalPages,
      incidents,
      stats
    });
  } catch (error) {
    console.error('Get incidents error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get incident statistics
// @route   GET /api/incidents/stats
// @access  Private
exports.getIncidentStats = async (req, res) => {
  try {
    const stats = await Incident.getStatistics();

    res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get incident stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get incident by ID
// @route   GET /api/incidents/:id
// @access  Private
exports.getIncidentById = async (req, res) => {
  try {
    const incident = await Incident.findById(req.params.id)
      .populate('assignedTo', 'name email avatar')
      .populate('createdBy', 'name email')
      .populate('relatedLogs')
      .populate('timeline.user', 'name email avatar')
      .populate('remediationSteps.assignedTo', 'name email');

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    if (!canAccessIncident(incident, req.user)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Incident is outside your scope.'
      });
    }

    res.status(200).json({
      success: true,
      incident
    });
  } catch (error) {
    console.error('Get incident by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get incident timeline
// @route   GET /api/incidents/:id/timeline
// @access  Private
exports.getIncidentTimeline = async (req, res) => {
  try {
    const incident = await Incident.findById(req.params.id)
      .populate('createdBy', 'name email avatar')
      .populate('assignedTo', 'name email avatar')
      .populate('relatedLogs', 'timestamp attackType sourceIP severity description targetSystem')
      .populate('timeline.user', 'name email avatar')
      .populate('remediationSteps.assignedTo', 'name email avatar');

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    if (!canAccessIncident(incident, req.user)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Incident is outside your scope.'
      });
    }

    const timelineEvents = [
      {
        type: 'incident_created',
        action: 'Incident created',
        note: incident.description,
        timestamp: incident.createdAt,
        user: incident.createdBy,
        source: 'incident'
      },
      ...(incident.timeline || []).map(event => ({
        type: 'timeline_event',
        action: event.action,
        note: event.note,
        timestamp: event.timestamp,
        user: event.user,
        attachments: event.attachments || [],
        source: 'timeline'
      })),
      ...(incident.relatedLogs || []).map(log => ({
        type: 'related_log',
        action: `Log observed: ${log.attackType}`,
        note: `${log.sourceIP} -> ${log.targetSystem} | ${log.description}`,
        timestamp: log.timestamp,
        log,
        source: 'log'
      })),
      ...(incident.remediationSteps || []).map(step => ({
        type: 'remediation_step',
        action: `Remediation step ${step.status}`,
        note: step.step,
        timestamp: step.completedAt || step.deadline || incident.updatedAt,
        user: step.assignedTo,
        source: 'remediation'
      }))
    ]
      .filter(event => event.timestamp)
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    res.status(200).json({
      success: true,
      incident: {
        ...incident.toObject(),
        timelineEvents
      }
    });
  } catch (error) {
    console.error('Get incident timeline error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Create new incident
// @route   POST /api/incidents
// @access  Private
exports.createIncident = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can create incidents.'
      });
    }

    const incidentData = { ...req.body };
    
    // Set created by
    incidentData.createdBy = req.user.id;

    // Create incident
    const incident = await Incident.create(incidentData);

    // Add initial timeline event
    await incident.addTimelineEvent(
      'Incident created',
      req.user.id,
      'Incident was created in the system'
    );

    // Populate references
    const populatedIncident = await Incident.findById(incident._id)
      .populate('createdBy', 'name email')
      .populate('assignedTo', 'name email');

    const systemGenerated = isSystemGeneratedIncident(incidentData);
    await recordAuditEvent(req, {
      systemAction: systemGenerated,
      action: systemGenerated ? 'Auto Incident Created' : 'Incident Created',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(populatedIncident._id),
      targetLabel: populatedIncident.title,
      details: `${systemGenerated ? 'Auto-created' : 'Created'} incident "${populatedIncident.title}"`,
      metadata: {
        severity: populatedIncident.severity,
        status: populatedIncident.status,
        sourceIP: populatedIncident.sourceIP,
        tags: populatedIncident.tags || []
      }
    });

    res.status(201).json({
      success: true,
      incident: populatedIncident
    });
  } catch (error) {
    console.error('Create incident error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Update incident
// @route   PUT /api/incidents/:id
// @access  Private
exports.updateIncident = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can edit incidents.'
      });
    }

    const { id } = req.params;
    const updateData = { ...req.body };
    if (updateData.archived === true) {
      updateData.archivedAt = new Date();
      updateData.archivedBy = req.user.id;
    }

    const incident = await Incident.findById(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    // Update incident
    Object.keys(updateData).forEach(key => {
      incident[key] = updateData[key];
    });

    await incident.save();

    // Add timeline event for update
    await incident.addTimelineEvent(
      updateData.archived === true ? 'Incident archived' : 'Incident updated',
      req.user.id,
      updateData.archived === true ? 'Incident was archived from the active queue' : 'Incident details were updated'
    );

    const populatedIncident = await Incident.findById(id)
      .populate('assignedTo', 'name email')
      .populate('createdBy', 'name email');

    await recordAuditEvent(req, {
      action: 'Incident Updated',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(incident._id),
      targetLabel: incident.title,
      details: `Updated incident "${incident.title}"`,
      metadata: { updatedFields: Object.keys(updateData) }
    });

    res.status(200).json({
      success: true,
      incident: populatedIncident
    });
  } catch (error) {
    console.error('Update incident error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Delete incident
// @route   DELETE /api/incidents/:id
// @access  Private
exports.deleteIncident = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can delete incidents.'
      });
    }

    const { id } = req.params;

    const incident = await Incident.findById(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    if (!canAccessIncident(incident, req.user)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Incident is outside your scope.'
      });
    }

    await Incident.findByIdAndDelete(id);

    await recordAuditEvent(req, {
      action: 'Incident Deleted',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(id),
      targetLabel: incident.title,
      details: `Deleted incident "${incident.title}"`,
      metadata: { severity: incident.severity, status: incident.status }
    });

    res.status(200).json({
      success: true,
      message: 'Incident deleted successfully'
    });
  } catch (error) {
    console.error('Delete incident error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Update incident status
// @route   PUT /api/incidents/:id/status
// @access  Private
exports.updateStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, note } = req.body;

    const incident = await Incident.findById(id);
    const oldStatus = incident?.status;

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    if (!canAccessIncident(incident, req.user)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Incident is outside your scope.'
      });
    }

    // Update status
    await incident.updateStatus(status, req.user.id, note);

    const populatedIncident = await Incident.findById(id)
      .populate('assignedTo', 'name email')
      .populate('createdBy', 'name email');

    await recordAuditEvent(req, {
      action: 'Incident Status Changed',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(incident._id),
      targetLabel: incident.title,
      details: `Status changed from ${oldStatus} to ${status} for "${incident.title}"`,
      metadata: { status, note }
    });

    res.status(200).json({
      success: true,
      incident: populatedIncident
    });
  } catch (error) {
    console.error('Update status error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Assign incident to user
// @route   PUT /api/incidents/:id/assign
// @access  Private
exports.assignIncident = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can assign incidents.'
      });
    }

    const { id } = req.params;
    const { userId, note } = req.body;

    const incident = await Incident.findById(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    let assignedUser = null;

    // Check if user exists
    if (userId) {
      assignedUser = await User.findById(userId);
      if (!assignedUser) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }
    }

    const oldAssignee = incident.assignedTo;
    incident.assignedTo = userId || null;

    // Add timeline event
    const assignNote = userId 
      ? `Incident assigned to user ${userId}`
      : 'Incident unassigned';
    
    await incident.addTimelineEvent(
      'Assignment changed',
      req.user.id,
      note || assignNote
    );

    await incident.save();

    const populatedIncident = await Incident.findById(id)
      .populate('assignedTo', 'name email avatar')
      .populate('createdBy', 'name email');

    let assignmentNotification = null;
    if (assignedUser) {
      const settings = await SystemSettings.getSingleton();
      const notifications = settings.notificationSettings || {};
      const shouldNotify = notifications.emailNotifications !== false
        && notifications.incidentAssignmentNotifications !== false;

      if (shouldNotify) {
        assignmentNotification = await sendIncidentAssignmentEmail({
          user: assignedUser,
          incident: populatedIncident,
          assignedBy: req.user?.email || req.user?.name || 'Admin',
          note
        });
      } else {
        assignmentNotification = { skipped: true, reason: 'Incident assignment notifications disabled in settings' };
      }
    }

    await recordAuditEvent(req, {
      action: 'Incident Assigned',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(incident._id),
      targetLabel: incident.title,
      details: userId
        ? `Incident assigned to ${userId}`
        : `Incident unassigned`,
      metadata: {
        userId: userId || null,
        note: note || '',
        notificationSent: Boolean(assignmentNotification?.sent),
        notificationSkipped: Boolean(assignmentNotification?.skipped),
        notificationReason: assignmentNotification?.reason || assignmentNotification?.error || ''
      }
    });

    res.status(200).json({
      success: true,
      incident: populatedIncident
    });
  } catch (error) {
    console.error('Assign incident error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Add timeline event
// @route   POST /api/incidents/:id/timeline
// @access  Private
exports.addTimelineEvent = async (req, res) => {
  try {
    const { id } = req.params;
    const { action, note, attachments = [] } = req.body;

    const incident = await Incident.findById(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    if (!canAccessIncident(incident, req.user)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Incident is outside your scope.'
      });
    }

    // Add timeline event
    await incident.addTimelineEvent(
      action,
      req.user.id,
      note,
      attachments
    );

    const populatedIncident = await Incident.findById(id)
      .populate('timeline.user', 'name email avatar');

    await recordAuditEvent(req, {
      action: 'Timeline Note Added',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(incident._id),
      targetLabel: incident.title,
      details: `Added timeline note to "${incident.title}"`,
      metadata: { timelineAction: action, hasAttachments: attachments.length > 0 }
    });

    res.status(200).json({
      success: true,
      incident: populatedIncident
    });
  } catch (error) {
    console.error('Add timeline event error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Add remediation step
// @route   POST /api/incidents/:id/remediation
// @access  Private
exports.addRemediationStep = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can add remediation steps.'
      });
    }

    const { id } = req.params;
    const { step, assignedTo, deadline, notes } = req.body;

    const incident = await Incident.findById(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    // Add remediation step
    incident.remediationSteps.push({
      step,
      assignedTo,
      deadline: deadline ? new Date(deadline) : null,
      notes,
      status: 'pending'
    });

    // Add timeline event
    await incident.addTimelineEvent(
      'Remediation step added',
      req.user.id,
      `Added remediation step: ${step}`
    );

    await incident.save();

    const populatedIncident = await Incident.findById(id)
      .populate('remediationSteps.assignedTo', 'name email');

    await recordAuditEvent(req, {
      action: 'Remediation Step Added',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(incident._id),
      targetLabel: incident.title,
      details: `Added remediation step to "${incident.title}"`,
      metadata: { step, assignedTo, deadline }
    });

    res.status(200).json({
      success: true,
      incident: populatedIncident
    });
  } catch (error) {
    console.error('Add remediation step error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Export incident report
// @route   GET /api/incidents/:id/export
// @access  Private
exports.exportIncident = async (req, res) => {
  try {
    const { id } = req.params;
    const { format = 'json' } = req.query;

    const incident = await Incident.findById(id)
      .populate('assignedTo', 'name email')
      .populate('createdBy', 'name email')
      .populate('relatedLogs')
      .populate('timeline.user', 'name email')
      .populate('remediationSteps.assignedTo', 'name email');

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    if (format === 'csv') {
      // Convert to CSV
      const headers = ['Field', 'Value'];
      let csv = headers.join(',') + '\n';
      
      const rows = [
        ['ID', incident._id],
        ['Title', incident.title],
        ['Description', incident.description],
        ['Severity', incident.severity],
        ['Status', incident.status],
        ['Category', incident.category],
        ['Source IP', incident.sourceIP],
        ['Created By', incident.createdBy?.name || 'N/A'],
        ['Assigned To', incident.assignedTo?.name || 'Unassigned'],
        ['Created At', incident.createdAt.toISOString()],
        ['Updated At', incident.updatedAt.toISOString()],
        ['Impact', incident.impact],
        ['Priority', incident.priority],
        ['Root Cause', incident.rootCause || 'N/A'],
        ['Lessons Learned', incident.lessonsLearned || 'N/A']
      ];
      
      rows.forEach(row => {
        csv += `"${row[0]}","${String(row[1]).replace(/"/g, '""')}"\n`;
      });

      // Add timeline
      csv += '\n"Timeline Events",""\n';
      incident.timeline.forEach(event => {
        csv += `"${event.timestamp.toISOString()} - ${event.action}","${event.note.replace(/"/g, '""')}"\n`;
      });

      // Add remediation steps
      csv += '\n"Remediation Steps",""\n';
      incident.remediationSteps.forEach(step => {
        csv += `"${step.step}","Status: ${step.status}"\n`;
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=incident-${incident._id}-${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csv);
    } else {
      // Return as JSON
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=incident-${incident._id}-${new Date().toISOString().split('T')[0]}.json`);
      res.send(JSON.stringify(incident, null, 2));
    }

    await recordAuditEvent(req, {
      action: 'Incident Report Exported',
      module: 'incidents',
      targetType: 'Incident',
      targetId: String(incident._id),
      targetLabel: incident.title,
      details: `Exported incident report as ${format.toUpperCase()}`,
      metadata: { format }
    });
  } catch (error) {
    console.error('Export incident error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
