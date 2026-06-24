const express = require('express');
const router = express.Router();
const { protect, authorizeRoles } = require('../middleware/auth');
const alertsController = require('../controllers/alertsController');

router.use(protect);

router.get('/recent', alertsController.getRecentAlerts);
router.get('/stats', alertsController.getAlertStats);
router.post('/', authorizeRoles('admin'), alertsController.createAlert);
router.patch('/bulk', authorizeRoles('admin'), alertsController.bulkUpdateAlerts);
router.get('/:id', alertsController.getAlertById);
router.patch('/:id', authorizeRoles('admin'), alertsController.updateAlert);
router.delete('/:id', authorizeRoles('admin'), alertsController.deleteAlert);

module.exports = router;
