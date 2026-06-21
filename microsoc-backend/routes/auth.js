const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect } = require('../middleware/auth');

// @route   POST /api/auth/register
// @desc    Register user
// @access  Public
router.post('/register', authController.register);

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', authController.login);

// @route   POST /api/auth/request-password-reset
// @desc    Send password reset OTP to user email
// @access  Public
router.post('/request-password-reset', authController.requestPasswordReset);

// @route   POST /api/auth/reset-password
// @desc    Change password using OTP
// @access  Public
router.post('/reset-password', authController.resetPassword);

// @route   GET /api/auth/approve/:token
// @desc    Approve pending user from admin email link
// @access  Public approval token
router.get('/approve/:token', authController.approveUser);

// @route   GET /api/auth/reject/:token
// @desc    Reject pending user from admin email link
// @access  Public approval token
router.get('/reject/:token', authController.rejectUser);

// @route   GET /api/auth/me
// @desc    Get current logged in user
// @access  Private
router.get('/me', protect, authController.getMe);

// @route   GET /api/auth/demo
// @desc    Get demo credentials
// @access  Public
router.get('/demo', authController.getDemoCredentials);

module.exports = router;
