const Log = require('../models/Log');
const User = require('../models/User');
const realtimeHub = require('../utils/realtimeHub');
const threatPipeline = require('../utils/threatPipeline');
const { recordAuditEvent } = require('../utils/auditLogger');

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
      sortOrder = 'desc',
      includeStats = 'false'
    } = req.query;

    // Build query
    const query = {
      archived: { $ne: true }
    };

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

    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const limitNumber = Math.min(5000, Math.max(1, parseInt(limit, 10) || 25));

    // Execute query with pagination
    const logs = await Log.find(query)
      .sort(sort)
      .limit(limitNumber)
      .skip((pageNumber - 1) * limitNumber)
      .lean();

    const total = await Log.countDocuments(query);
    const totalPages = Math.ceil(total / limitNumber);

    const shouldIncludeStats = String(includeStats).toLowerCase() === 'true';
    const stats = shouldIncludeStats ? await Log.getStatistics(timeRange) : undefined;

    const payload = {
      success: true,
      count: logs.length,
      total,
      page: pageNumber,
      totalPages,
      logs: logs.map(log => ({ ...log, id: String(log._id) }))
    };
    if (shouldIncludeStats) payload.stats = stats;

    res.status(200).json(payload);
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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can create logs.'
      });
    }

    const logData = threatPipeline.validateLogPayload(req.body);
    
    // Set processed by if not specified
    if (!logData.processedBy) {
      logData.processedBy = req.user.id;
      logData.processedAt = new Date();
    }

    const log = await Log.create(logData);
    realtimeHub.broadcast({ type: 'new-log', log });
    const pipelineResult = await threatPipeline.analyzeLogNow(log, {
      userId: req.user.id,
      source: 'api'
    });

    await recordAuditEvent(req, {
      action: 'Security Log Created',
      module: 'logs',
      targetType: 'Log',
      targetId: String(log._id),
      targetLabel: `${log.attackType} · ${log.sourceIP}`,
      details: `Created security log for ${log.attackType}`,
      metadata: { severity: log.severity, sourceIP: log.sourceIP, targetSystem: log.targetSystem }
    });

    res.status(201).json({
      success: true,
      log,
      pipeline: {
        completed: true,
        detections: pipelineResult.detections?.length || 0,
        incidents: pipelineResult.incidents || [],
        incidentCreated: Boolean((pipelineResult.incidents || []).some(item => item.created))
      }
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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can update logs.'
      });
    }

    const { id } = req.params;
    const updateData = { ...req.body };
    if (updateData.archived === true) {
      updateData.archivedAt = new Date();
      updateData.archivedBy = req.user.id;
    }

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

    await recordAuditEvent(req, {
      action: 'Security Log Updated',
      module: 'logs',
      targetType: 'Log',
      targetId: String(log._id),
      targetLabel: `${log.attackType} · ${log.sourceIP}`,
      details: `Updated security log ${log.attackType}`,
      metadata: { updatedFields: Object.keys(updateData) }
    });

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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can delete logs.'
      });
    }

    const { id } = req.params;

    const log = await Log.findByIdAndDelete(id);

    if (!log) {
      return res.status(404).json({
        success: false,
        message: 'Log not found'
      });
    }

    await recordAuditEvent(req, {
      action: 'Security Log Deleted',
      module: 'logs',
      targetType: 'Log',
      targetId: String(id),
      targetLabel: `${log.attackType} · ${log.sourceIP}`,
      details: `Deleted security log ${log.attackType}`,
      metadata: { severity: log.severity, sourceIP: log.sourceIP }
    });

    res.status(200).json({
      success: true,
      deletedCount: 1,
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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can create logs in bulk.'
      });
    }

    const logsData = req.body;

    if (!Array.isArray(logsData)) {
      return res.status(400).json({
        success: false,
        message: 'Request body must be an array of logs'
      });
    }

    // Normalize bulk/live-stream payloads the same way as single log creation so
    // threshold correlation sees stable attack names, IPs, and target systems.
    const logsWithUser = logsData.map(log => ({
      ...threatPipeline.validateLogPayload(log),
      processedBy: req.user.id,
      processedAt: new Date()
    }));

    const logs = await Log.insertMany(logsWithUser);
    logs.forEach(log => realtimeHub.broadcast({ type: 'new-log', log }));
    const pipelineResults = await threatPipeline.analyzeBatchNow(logs, {
      userId: req.user.id,
      source: 'bulk'
    });

    await recordAuditEvent(req, {
      systemAction: true,
      action: 'Bulk Logs Created',
      module: 'logs',
      targetType: 'Log Batch',
      targetLabel: `${logs.length} logs`,
      details: `System ingested ${logs.length} security logs`,
      metadata: {
        count: logs.length,
        source: 'bulk-live-stream',
        submittedBy: req.user?.email || req.user?.name || 'admin'
      }
    });

    res.status(201).json({
      success: true,
      count: logs.length,
      logs,
      pipeline: {
        completed: true,
        analyzed: pipelineResults.length,
        detections: pipelineResults.reduce((sum, result) => sum + (result.detections?.length || 0), 0),
        alerts: pipelineResults.flatMap(result => result.alerts || []),
        incidents: pipelineResults.flatMap(result => result.incidents || []),
        incidentCreated: pipelineResults.some(result => (result.incidents || []).some(item => item.created))
      }
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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can delete logs.'
      });
    }

    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an array of log IDs to delete'
      });
    }

    const result = await Log.deleteMany({ _id: { $in: ids } });

    await recordAuditEvent(req, {
      action: 'Bulk Logs Deleted',
      module: 'logs',
      targetType: 'Log Batch',
      targetLabel: `${ids.length} logs`,
      details: `Deleted ${result.deletedCount} logs`,
      metadata: { ids }
    });

    res.status(200).json({
      success: true,
      deletedCount: result.deletedCount,
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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can generate mock logs.'
      });
    }

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
    createdLogs.forEach(log => realtimeHub.broadcast({ type: 'new-log', log }));
    const pipelineResults = await threatPipeline.analyzeBatchNow(createdLogs, {
      userId: req.user.id,
      source: 'mock'
    });

    await recordAuditEvent(req, {
      systemAction: true,
      action: 'Mock Logs Generated',
      module: 'logs',
      targetType: 'Log Batch',
      targetLabel: `${createdLogs.length} mock logs`,
      details: `System generated ${createdLogs.length} mock security logs`,
      metadata: {
        count: createdLogs.length,
        source: 'mock-generator',
        submittedBy: req.user?.email || req.user?.name || 'admin'
      }
    });

    res.status(201).json({
      success: true,
      count: createdLogs.length,
      logs: createdLogs,
      pipeline: {
        completed: true,
        analyzed: pipelineResults.length,
        detections: pipelineResults.reduce((sum, result) => sum + (result.detections?.length || 0), 0),
        alerts: pipelineResults.flatMap(result => result.alerts || []),
        incidents: pipelineResults.flatMap(result => result.incidents || []),
        incidentCreated: pipelineResults.some(result => (result.incidents || []).some(item => item.created))
      }
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
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can export logs.'
      });
    }

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

    await recordAuditEvent(req, {
      action: 'Logs Exported',
      module: 'logs',
      targetType: 'Report',
      targetLabel: 'Security logs export',
      details: `Exported logs as ${String(format).toUpperCase()}`,
      metadata: { format, filters }
    });
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
      const log = await realtimeHub.createDemoLog(req.user.id);
      
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
