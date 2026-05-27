const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const analyticsController = require('../controllers/analyticsController');

// All routes require authentication
router.use(auth);

// @route   GET /api/analytics/overview
// @desc    Get analytics overview
// @access  Private
router.get('/overview', analyticsController.getOverview);

// @route   GET /api/analytics/attack-distribution
// @desc    Get attack distribution
// @access  Private
router.get('/attack-distribution', analyticsController.getAttackDistribution);

// @route   GET /api/analytics/threat-timeline
// @desc    Get threat timeline
// @access  Private
router.get('/threat-timeline', analyticsController.getThreatTimeline);

// @route   GET /api/analytics/patterns
// @desc    Get attack patterns
// @access  Private
router.get('/patterns', analyticsController.getPatterns);

// @route   GET /api/analytics/top-attackers
// @desc    Get top attackers
// @access  Private
router.get('/top-attackers', analyticsController.getTopAttackers);

// @route   GET /api/analytics/anomalies
// @desc    Get anomalies
// @access  Private
router.get('/anomalies', analyticsController.getAnomalies);

// @route   GET /api/analytics/remediations
// @desc    Get remediation suggestions
// @access  Private
router.get('/remediations', analyticsController.getRemediations);

// @route   GET /api/analytics/predictions
// @desc    Get predictions
// @access  Private
router.get('/predictions', analyticsController.getPredictions);

// @route   GET /api/analytics/ai-insights
// @desc    Get AI insights
// @access  Private
router.get('/ai-insights', analyticsController.getAIInsights);

// @route   POST /api/analytics/generate
// @desc    Generate analytics
// @access  Private
router.post('/generate', analyticsController.generateAnalytics);

// @route   GET /api/analytics/export
// @desc    Export analytics report
// @access  Private
router.get('/export', analyticsController.exportAnalytics);

module.exports = router;