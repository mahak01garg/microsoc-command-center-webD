const express = require('express');
const router = express.Router();
const { protect, authorizeRoles } = require('../middleware/auth');
const logController = require('../controllers/logController');

// All routes require authentication
router.use(protect);

// @route   GET /api/logs
// @desc    Get all logs with filters
// @access  Private
router.get('/', logController.getLogs);

// @route   GET /api/logs/stats
// @desc    Get log statistics
// @access  Private
router.get('/stats', logController.getLogStats);

// @route   GET /api/logs/stream
// @desc    Stream real-time logs
// @access  Private
router.get('/stream', logController.streamLogs);

// @route   POST /api/logs
// @desc    Create new log
// @access  Admin
router.post('/', authorizeRoles('admin'), logController.createLog);

// @route   PUT /api/logs/:id
// @desc    Update log
// @access  Admin
router.put('/:id', authorizeRoles('admin'), logController.updateLog);

// @route   DELETE /api/logs/:id
// @desc    Delete log
// @access  Admin
router.delete('/:id', authorizeRoles('admin'), logController.deleteLog);

// @route   POST /api/logs/bulk
// @desc    Create multiple logs
// @access  Admin
router.post('/bulk', authorizeRoles('admin'), logController.createBulkLogs);

// @route   DELETE /api/logs
// @desc    Delete multiple logs
// @access  Admin
router.delete('/', authorizeRoles('admin'), logController.deleteMultipleLogs);

// @route   POST /api/logs/generate-mock
// @desc    Generate mock logs
// @access  Admin
router.post('/generate-mock', authorizeRoles('admin'), logController.generateMockLogs);

// @route   GET /api/logs/export
// @desc    Export logs
// @access  Admin
router.get('/export', authorizeRoles('admin'), logController.exportLogs);

// @route   GET /api/logs/:id
// @desc    Get single log by ID
// @access  Private
router.get('/:id', logController.getLogById);

module.exports = router;
