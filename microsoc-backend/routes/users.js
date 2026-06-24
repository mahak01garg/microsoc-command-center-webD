const express = require('express');
const router = express.Router();
const { protect, authorizeRoles } = require('../middleware/auth');
const userController = require('../controllers/userController');

router.use(protect);
router.use(authorizeRoles('admin'));

router.get('/', userController.getUsers);
router.patch('/:id/access', userController.updateUserAccess);

module.exports = router;
