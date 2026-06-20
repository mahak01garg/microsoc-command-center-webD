const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const aiController = require('../controllers/aiController');

// Log explanation is intentionally available without session auth so the
// action never fails because of an expired dashboard login token.
router.post('/explain-log', aiController.explainLog);

router.use(protect);
router.post('/triage-incident', aiController.triageIncident);
router.post('/generate-report', aiController.generateReport);
router.post('/chat', aiController.chat);
router.post('/natural-search', aiController.naturalSearch);

module.exports = router;
