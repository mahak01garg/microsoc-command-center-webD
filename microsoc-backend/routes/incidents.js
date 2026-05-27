const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const incidentController = require('../controllers/incidentController');

// All routes require authentication
router.use(auth);

// @route   GET /api/incidents
// @desc    Get all incidents
// @access  Private
router.get('/', incidentController.getIncidents);

// @route   GET /api/incidents/stats
// @desc    Get incident statistics
// @access  Private
router.get('/stats', incidentController.getIncidentStats);

// @route   GET /api/incidents/:id
// @desc    Get incident by ID
// @access  Private
router.get('/:id', incidentController.getIncidentById);

// @route   POST /api/incidents
// @desc    Create new incident
// @access  Private
router.post('/', incidentController.createIncident);

// @route   PUT /api/incidents/:id
// @desc    Update incident
// @access  Private
router.put('/:id', incidentController.updateIncident);

// @route   DELETE /api/incidents/:id
// @desc    Delete incident
// @access  Private
router.delete('/:id', incidentController.deleteIncident);

// @route   PUT /api/incidents/:id/status
// @desc    Update incident status
// @access  Private
router.put('/:id/status', incidentController.updateStatus);

// @route   PUT /api/incidents/:id/assign
// @desc    Assign incident to user
// @access  Private
router.put('/:id/assign', incidentController.assignIncident);

// @route   POST /api/incidents/:id/timeline
// @desc    Add timeline event
// @access  Private
router.post('/:id/timeline', incidentController.addTimelineEvent);

// @route   POST /api/incidents/:id/remediation
// @desc    Add remediation step
// @access  Private
router.post('/:id/remediation', incidentController.addRemediationStep);

// @route   GET /api/incidents/:id/export
// @desc    Export incident report
// @access  Private
router.get('/:id/export', incidentController.exportIncident);

module.exports = router;