const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const dashboardController = require('../controllers/dashboardController');

// All routes require authentication
router.use(auth);

// @route   GET /api/dashboard/stats
// @desc    Get dashboard statistics
// @access  Private
router.get('/stats', dashboardController.getDashboardStats);

// @route   GET /api/dashboard/realtime
// @desc    Get real-time data
// @access  Private
router.get('/realtime', dashboardController.getRealtimeData);

// @route   GET /api/dashboard/activity
// @desc    Get recent activity
// @access  Private
router.get('/activity', dashboardController.getRecentActivity);

// @route   GET /api/dashboard/alerts
// @desc    Get recent alerts
// @access  Private
router.get('/alerts', dashboardController.getRecentAlerts);

module.exports = router;