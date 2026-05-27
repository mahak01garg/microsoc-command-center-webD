const Log = require('../models/Log');
const User = require('../models/User');

// @desc    Get all logs with filters
// @route   GET /api/logs
// @access  Private
exports.getLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 25,
      severity,
      attackType,
      sourceIP,
      timeRange = '24h',
      search,
      sortBy = 'timestamp',
      sortOrder = 'desc'
    } = req.query;

    // Build query
    const query = {};

    // Time range filter
    const now = new Date();
    let startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000)); // Default 24h
    
    switch(timeRange) {
      case '1h':
        startDate = new Date(now.getTime() - (60 * 60 * 1000));
        break;
      case '7d':
        startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
        break;
      case '30d':
        startDate = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
        break;
      case 'all':
        startDate = null;
        break;
    }

    if (startDate) {
      query.timestamp = { $gte: startDate };
    }

    // Severity filter
    if (severity) {
      const severities = Array.isArray(severity) ? severity : [severity];
      query.severity = { $in: severities };
    }

    // Attack type filter
    if (attackType) {
      const attackTypes = Array.isArray(attackType) ? attackType : [attackType];
      query.attackType = { $in: attackTypes };
    }

    // Source IP filter
    if (sourceIP) {
      query.sourceIP = { $regex: sourceIP, $options: 'i' };
    }

    // Search filter
    if (search) {
      query.$or = [
        { description: { $regex: search, $options: 'i' } },
        { sourceIP: { $regex: search, $options: 'i' } },
        { targetSystem: { $regex: search, $options: 'i' } },
        { country: { $regex: search, $options: 'i' } }
      ];
    }

    // Sort
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    // Execute query with pagination
    const logs = await Log.find(query)
      .sort(sort)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Log.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get statistics for current filters
    const stats = await Log.getStatistics(timeRange);

    res.status(200).json({
      success: true,
      count: logs.length,
      total,
      page: parseInt(page),
      totalPages,
      logs,
      stats
    });
  } catch (error) {
    console.error('Get logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get log statistics
// @route   GET /api/logs/stats
// @access  Private
exports.getLogStats = async (req, res) => {
  try {
    const { timeRange = '24h' } = req.query;
    
    const stats = await Log.getStatistics(timeRange);

    res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get log stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Get single log by ID
// @route   GET /api/logs/:id
// @access  Private
exports.getLogById = async (req, res) => {
  try {
    const log = await Log.findById(req.params.id);

    if (!log) {
      return res.status(404).json({
        success: false,
        message: 'Log not found'
      });
    }

    res.status(200).json({
      success: true,
      log
    });
  } catch (error) {
    console.error('Get log by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Create new log
// @route   POST /api/logs
// @access  Private
exports.createLog = async (req, res) => {
  try {
    const logData = req.body;
    
    // Set processed by if not specified
    if (!logData.processedBy) {
      logData.processedBy = req.user.id;
      logData.processedAt = new Date();
    }

    const log = await Log.create(logData);

    res.status(201).json({
      success: true,
      log
    });
  } catch (error) {
    console.error('Create log error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Update log
// @route   PUT /api/logs/:id
// @access  Private
exports.updateLog = async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    const log = await Log.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!log) {
      return res.status(404).json({
        success: false,
        message: 'Log not found'
      });
    }

    res.status(200).json({
      success: true,
      log
    });
  } catch (error) {
    console.error('Update log error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Delete log
// @route   DELETE /api/logs/:id
// @access  Private
exports.deleteLog = async (req, res) => {
  try {
    const { id } = req.params;

    const log = await Log.findByIdAndDelete(id);

    if (!log) {
      return res.status(404).json({
        success: false,
        message: 'Log not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Log deleted successfully'
    });
  } catch (error) {
    console.error('Delete log error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Create multiple logs
// @route   POST /api/logs/bulk
// @access  Private
exports.createBulkLogs = async (req, res) => {
  try {
    const logsData = req.body;

    if (!Array.isArray(logsData)) {
      return res.status(400).json({
        success: false,
        message: 'Request body must be an array of logs'
      });
    }

    // Add processed by to each log
    const logsWithUser = logsData.map(log => ({
      ...log,
      processedBy: req.user.id,
      processedAt: new Date()
    }));

    const logs = await Log.insertMany(logsWithUser);

    res.status(201).json({
      success: true,
      count: logs.length,
      logs
    });
  } catch (error) {
    console.error('Create bulk logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Delete multiple logs
// @route   DELETE /api/logs
// @access  Private
exports.deleteMultipleLogs = async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of log IDs to delete'
      });
    }

    const result = await Log.deleteMany({ _id: { $in: ids } });

    res.status(200).json({
      success: true,
      message: `${result.deletedCount} logs deleted successfully`
    });
  } catch (error) {
    console.error('Delete multiple logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Generate mock logs
// @route   POST /api/logs/generate-mock
// @access  Private
exports.generateMockLogs = async (req, res) => {
  try {
    const { count = 10 } = req.body;

    if (count > 1000) {
      return res.status(400).json({
        success: false,
        message: 'Cannot generate more than 1000 logs at once'
      });
    }

    const logs = [];
    for (let i = 0; i < count; i++) {
      const mockLog = Log.generateMockLog();
      mockLog.processedBy = req.user.id;
      mockLog.processedAt = new Date();
      logs.push(mockLog);
    }

    const createdLogs = await Log.insertMany(logs);

    res.status(201).json({
      success: true,
      count: createdLogs.length,
      logs: createdLogs
    });
  } catch (error) {
    console.error('Generate mock logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Export logs
// @route   GET /api/logs/export
// @access  Private
exports.exportLogs = async (req, res) => {
  try {
    const { format = 'json', ...filters } = req.query;

    // Build query from filters
    const query = {};
    
    if (filters.severity) {
      const severities = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
      query.severity = { $in: severities };
    }

    if (filters.attackType) {
      const attackTypes = Array.isArray(filters.attackType) ? filters.attackType : [filters.attackType];
      query.attackType = { $in: attackTypes };
    }

    if (filters.timeRange && filters.timeRange !== 'all') {
      const now = new Date();
      let startDate;
      
      switch(filters.timeRange) {
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
      }
      
      if (startDate) {
        query.timestamp = { $gte: startDate };
      }
    }

    const logs = await Log.find(query).sort({ timestamp: -1 });

    if (format === 'csv') {
      // Convert to CSV
      const headers = ['Timestamp', 'Attack Type', 'Source IP', 'Target System', 'Severity', 'Country', 'Description', 'Blocked'];
      
      let csv = headers.join(',') + '\n';
      
      logs.forEach(log => {
        const row = [
          log.timestamp.toISOString(),
          log.attackType,
          log.sourceIP,
          log.targetSystem,
          log.severity,
          log.country,
          `"${log.description.replace(/"/g, '""')}"`,
          log.isBlocked ? 'Yes' : 'No'
        ];
        csv += row.join(',') + '\n';
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=logs-${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csv);
    } else {
      // Return as JSON
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=logs-${new Date().toISOString().split('T')[0]}.json`);
      res.send(JSON.stringify(logs, null, 2));
    }
  } catch (error) {
    console.error('Export logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Stream real-time logs
// @route   GET /api/logs/stream
// @access  Private
exports.streamLogs = async (req, res) => {
  try {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Send initial data
    const recentLogs = await Log.find()
      .sort({ timestamp: -1 })
      .limit(10);
    
    res.write(`data: ${JSON.stringify({ type: 'initial', logs: recentLogs })}\n\n`);

    // Mock real-time updates every 5 seconds
    const interval = setInterval(async () => {
      const mockLog = Log.generateMockLog();
      mockLog.processedBy = req.user.id;
      mockLog.processedAt = new Date();
      
      const log = await Log.create(mockLog);
      
      res.write(`data: ${JSON.stringify({ type: 'new', log })}\n\n`);
    }, 5001);

    // Clean up on client disconnect
    req.on('close', () => {
      clearInterval(interval);
      res.end();
    });
  } catch (error) {
    console.error('Stream logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};