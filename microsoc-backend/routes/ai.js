const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const aiController = require('../controllers/aiController');

router.use(protect);

router.post('/explain-log', aiController.explainLog);
router.post('/triage-incident', aiController.triageIncident);
router.post('/generate-report', aiController.generateReport);
router.post('/chat', aiController.chat);
router.post('/natural-search', aiController.naturalSearch);

module.exports = router;
