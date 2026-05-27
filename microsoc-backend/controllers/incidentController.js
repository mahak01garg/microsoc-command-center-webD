const Incident = require('../models/Incident');
const Log = require('../models/Log');
const User = require('../models/User');

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
    const query = {};

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
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { sourceIP: { $regex: search, $options: 'i' } }
      ];
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

// @desc    Create new incident
// @route   POST /api/incidents
// @access  Private
exports.createIncident = async (req, res) => {
  try {
    const incidentData = req.body;
    
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
    const { id } = req.params;
    const updateData = req.body;

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
      'Incident updated',
      req.user.id,
      'Incident details were updated'
    );

    const populatedIncident = await Incident.findById(id)
      .populate('assignedTo', 'name email')
      .populate('createdBy', 'name email');

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
    const { id } = req.params;

    const incident = await Incident.findByIdAndDelete(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

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

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    // Update status
    await incident.updateStatus(status, req.user.id, note);

    const populatedIncident = await Incident.findById(id)
      .populate('assignedTo', 'name email')
      .populate('createdBy', 'name email');

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
    const { id } = req.params;
    const { userId, note } = req.body;

    const incident = await Incident.findById(id);

    if (!incident) {
      return res.status(404).json({
        success: false,
        message: 'Incident not found'
      });
    }

    // Check if user exists
    if (userId) {
      const user = await User.findById(userId);
      if (!user) {
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

    // Add timeline event
    await incident.addTimelineEvent(
      action,
      req.user.id,
      note,
      attachments
    );

    const populatedIncident = await Incident.findById(id)
      .populate('timeline.user', 'name email avatar');

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
  } catch (error) {
    console.error('Export incident error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};