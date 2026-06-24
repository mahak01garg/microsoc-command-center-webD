const express = require('express');
const router = express.Router();
const { protect, authorizeRoles } = require('../middleware/auth');
const settingsController = require('../controllers/settingsController');

router.use(protect);
router.use(authorizeRoles('admin'));

router.get('/', settingsController.getSettings);
router.patch('/', settingsController.updateSettings);

module.exports = router;
