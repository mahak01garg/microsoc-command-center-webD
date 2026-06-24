const express = require('express');
const router = express.Router();
const { protect, authorizeRoles } = require('../middleware/auth');
const auditController = require('../controllers/auditController');

router.use(protect);
router.use(authorizeRoles('admin'));

router.get('/', auditController.getAuditLogs);
router.get('/stats', auditController.getAuditLogStats);

module.exports = router;
