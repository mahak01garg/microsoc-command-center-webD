const Alert = require('../models/Alert');

function buildTimeWindow(timeRange = '24h') {
  const now = new Date();
  switch (timeRange) {
    case '1h':
      return new Date(now.getTime() - (60 * 60 * 1000));
    case '24h':
      return new Date(now.getTime() - (24 * 60 * 60 * 1000));
    case '7d':
      return new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
    case '30d':
      return new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
    default:
      return new Date(now.getTime() - (24 * 60 * 60 * 1000));
  }
}

function buildQuery(req) {
  const {
    status,
    severity,
    sourceIP,
    attackType,
    search,
    timeRange = '24h'
  } = req.query;

  const query = {
    deletedAt: { $exists: false }
  };

  const startDate = buildTimeWindow(timeRange);
  if (startDate) {
    query.lastSeen = { $gte: startDate };
  }

  if (status && status !== 'all') {
    query.status = Array.isArray(status) ? { $in: status } : status;
  }

  if (severity && severity !== 'all') {
    query.severity = Array.isArray(severity) ? { $in: severity } : severity;
  }

  if (sourceIP) {
    query.sourceIP = { $regex: sourceIP, $options: 'i' };
  }

  if (attackType) {
    query.attackType = { $regex: attackType, $options: 'i' };
  }

  if (search) {
    query.$or = [
      { title: { $regex: search, $options: 'i' } },
      { description: { $regex: search, $options: 'i' } },
      { sourceIP: { $regex: search, $options: 'i' } },
      { targetSystem: { $regex: search, $options: 'i' } },
      { attackType: { $regex: search, $options: 'i' } }
    ];
  }

  return { query, timeRange };
}

exports.getRecentAlerts = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      sortBy = 'lastSeen',
      sortOrder = 'desc'
    } = req.query;

    const { query, timeRange } = buildQuery(req);
    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const limitNumber = Math.min(500, Math.max(1, parseInt(limit, 10) || 50));
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const alerts = await Alert.find(query)
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity')
      .sort(sort)
      .limit(limitNumber)
      .skip((pageNumber - 1) * limitNumber)
      .lean();

    const total = await Alert.countDocuments(query);
    const totalPages = Math.ceil(total / limitNumber);
    const stats = await Alert.getStatistics(timeRange);

    res.status(200).json({
      success: true,
      count: alerts.length,
      total,
      page: pageNumber,
      totalPages,
      alerts: alerts.map(alert => ({ ...alert, id: String(alert._id) })),
      stats
    });
  } catch (error) {
    console.error('Get recent alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.getAlertById = async (req, res) => {
  try {
    const alert = await Alert.findOne({
      _id: req.params.id,
      deletedAt: { $exists: false }
    })
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity description')
      .populate('reviewedBy', 'name email')
      .populate('deletedBy', 'name email')
      .populate('notes.user', 'name email');

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    res.status(200).json({
      success: true,
      alert
    });
  } catch (error) {
    console.error('Get alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.getAlertStats = async (req, res) => {
  try {
    const { timeRange = '24h' } = req.query;
    const stats = await Alert.getStatistics(timeRange);
    res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get alert stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.createAlert = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can create alerts.'
      });
    }

    const alert = await Alert.create({
      ...req.body,
      status: req.body.status || 'new'
    });
    res.status(201).json({
      success: true,
      alert
    });
  } catch (error) {
    console.error('Create alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.updateAlert = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can update alerts.'
      });
    }

    const alert = await Alert.findOne({
      _id: req.params.id,
      deletedAt: { $exists: false }
    });

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    const { status, severity, notes, reviewedAt, reviewedBy, ...rest } = req.body;

    Object.assign(alert, rest);

    if (severity) alert.severity = severity;
    if (status) alert.status = status;
    if (Array.isArray(notes) && notes.length) {
      notes.forEach(note => {
        alert.notes.push({
          text: note.text || note,
          user: req.user.id
        });
      });
    }

    if (reviewedAt) alert.reviewedAt = reviewedAt;
    if (reviewedBy) alert.reviewedBy = reviewedBy;

    await alert.save();

    const populated = await Alert.findById(alert._id)
      .populate('incident', 'title status severity')
      .populate('log', 'timestamp attackType sourceIP severity');

    res.status(200).json({
      success: true,
      alert: populated
    });
  } catch (error) {
    console.error('Update alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.bulkUpdateAlerts = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can update alerts in bulk.'
      });
    }

    const { ids, status, severity, note } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide alert IDs'
      });
    }

    const alerts = await Alert.find({
      _id: { $in: ids },
      deletedAt: { $exists: false }
    });

    for (const alert of alerts) {
      if (status) alert.status = status;
      if (severity) alert.severity = severity;
      if (note) {
        alert.notes.push({
          text: note,
          user: req.user.id
        });
      }
      await alert.save();
    }

    res.status(200).json({
      success: true,
      count: alerts.length,
      message: `${alerts.length} alerts updated successfully`
    });
  } catch (error) {
    console.error('Bulk update alerts error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.deleteAlert = async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can archive alerts.'
      });
    }

    const alert = await Alert.findOne({
      _id: req.params.id,
      deletedAt: { $exists: false }
    });

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    await alert.softDelete(req.user.id, req.body?.reason);

    res.status(200).json({
      success: true,
      message: 'Alert archived successfully'
    });
  } catch (error) {
    console.error('Delete alert error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
