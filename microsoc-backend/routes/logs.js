const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const logController = require('../controllers/logController');

// All routes require authentication
router.use(auth);

// @route   GET /api/logs
// @desc    Get all logs with filters
// @access  Private
router.get('/', logController.getLogs);

// @route   GET /api/logs/stats
// @desc    Get log statistics
// @access  Private
router.get('/stats', logController.getLogStats);

// @route   GET /api/logs/:id
// @desc    Get single log by ID
// @access  Private
router.get('/:id', logController.getLogById);

// @route   POST /api/logs
// @desc    Create new log
// @access  Private
router.post('/', logController.createLog);

// @route   PUT /api/logs/:id
// @desc    Update log
// @access  Private
router.put('/:id', logController.updateLog);

// @route   DELETE /api/logs/:id
// @desc    Delete log
// @access  Private
router.delete('/:id', logController.deleteLog);

// @route   POST /api/logs/bulk
// @desc    Create multiple logs
// @access  Private
router.post('/bulk', logController.createBulkLogs);

// @route   DELETE /api/logs
// @desc    Delete multiple logs
// @access  Private
router.delete('/', logController.deleteMultipleLogs);

// @route   POST /api/logs/generate-mock
// @desc    Generate mock logs
// @access  Private
router.post('/generate-mock', logController.generateMockLogs);

// @route   GET /api/logs/export
// @desc    Export logs
// @access  Private
router.get('/export', logController.exportLogs);

// @route   GET /api/logs/stream
// @desc    Stream real-time logs
// @access  Private
router.get('/stream', logController.streamLogs);

module.exports = router;