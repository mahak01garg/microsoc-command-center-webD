const User = require('../models/User');
const crypto = require('crypto');
const { recordAuditEvent, pickRequestIp } = require('../utils/auditLogger');
const {
  sendApprovalRequestEmail,
  sendPasswordResetOtpEmail,
  sendAccessDecisionEmail
} = require('../utils/approvalMailer');

async function recordLoginFailure(req, email, reason, user = null) {
  const normalizedEmail = String(email || '').trim().toLowerCase() || 'unknown';
  await recordAuditEvent(req, {
    actor: user?._id || null,
    actorName: user?.name || 'Unknown User',
    actorEmail: user?.email || normalizedEmail,
    actorRole: user?.role || 'unknown',
    action: 'User Login Failed',
    module: 'auth',
    targetType: 'Login Attempt',
    targetId: normalizedEmail,
    targetLabel: normalizedEmail,
    result: 'failure',
    details: `Authentication failed for ${normalizedEmail}: ${reason}`,
    ipAddress: pickRequestIp(req),
    userAgent: req.headers?.['user-agent'] || '',
    metadata: {
      reason,
      authenticationMethod: 'Email + Password',
      emailKnown: Boolean(user)
    }
  });
}

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const normalizedEmail = String(email || '').trim().toLowerCase();

    // Check if user already exists
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    const user = new User({
      name,
      email: normalizedEmail,
      password,
      role: 'analyst',
      approvalStatus: 'pending'
    });
    const approvalToken = user.createApprovalToken();
    await user.save();

    const approvalEmail = await sendApprovalRequestEmail({
      req,
      user,
      token: approvalToken
    });

    res.status(201).json({
      success: true,
      message: approvalEmail.sent
        ? 'Signup request sent for admin approval. You can login after approval.'
        : 'Signup request created. Admin approval is required before login.',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        approvalStatus: user.approvalStatus
      }
    });

    await recordAuditEvent(req, {
      actor: null,
      actorName: user.name,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'User Added',
      module: 'users',
      targetType: 'User',
      targetId: String(user._id),
      targetLabel: user.email,
      details: `New user registration requested for ${user.email}`,
      metadata: { approvalStatus: user.approvalStatus }
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = String(email || '').trim().toLowerCase();

    // Check if user exists
    const user = await User.findOne({ email: normalizedEmail }).select('+password');
    if (!user) {
      await recordLoginFailure(req, normalizedEmail, 'Invalid credentials: user not found');
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      await recordLoginFailure(req, normalizedEmail, 'Account is deactivated', user);
      return res.status(403).json({
        success: false,
        message: 'Account is deactivated'
      });
    }

    if (user.approvalStatus === 'pending') {
      await recordLoginFailure(req, normalizedEmail, 'Account pending admin approval', user);
      return res.status(403).json({
        success: false,
        message: 'Your account is waiting for admin approval'
      });
    }

    if (user.approvalStatus === 'rejected') {
      await recordLoginFailure(req, normalizedEmail, 'Account approval rejected', user);
      return res.status(403).json({
        success: false,
        message: 'Your account approval request was rejected'
      });
    }

    // Check password
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      await recordLoginFailure(req, normalizedEmail, 'Invalid credentials: password mismatch', user);
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Create token
    const token = user.getSignedJwtToken();
    const sessionId = `${String(user._id).slice(-8)}-${Date.now().toString(36)}`;

    // Update login history
    await user.updateLoginHistory(
      pickRequestIp(req),
      req.headers['user-agent']
    );

    // Remove password from response
    user.password = undefined;

    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
        preferences: user.preferences,
        lastLogin: user.lastLogin
      }
    });

    await recordAuditEvent(req, {
      actor: user._id,
      actorName: user.name,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'User Logged In',
      module: 'auth',
      targetType: 'Session',
      targetId: sessionId,
      targetLabel: user.email,
      details: `Authentication successful. Role: ${user.role}. Access granted.`,
      metadata: {
        loginCount: user.loginCount,
        authenticationMethod: 'Email + Password',
        role: user.role,
        sessionId,
        sessionDuration: 'Not Captured'
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
        preferences: user.preferences,
        lastLogin: user.lastLogin,
        loginCount: user.loginCount
      }
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Send password reset OTP to user's email
// @route   POST /api/auth/request-password-reset
// @access  Public
exports.requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = String(email || '').trim().toLowerCase();

    if (!normalizedEmail) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const user = await User.findOne({ email: normalizedEmail }).select('+passwordResetOtp +passwordResetOtpExpires');

    if (user) {
      const otp = user.createPasswordResetOtp();
      await user.save();
      const emailResult = await sendPasswordResetOtpEmail({ user, otp });

      if (!emailResult.sent) {
        return res.status(500).json({
          success: false,
          message: emailResult.error || 'OTP email delivery failed. Please try again later.'
        });
      }
    }

    res.status(200).json({
      success: true,
      message: 'If this email is registered, an OTP has been sent.'
    });
  } catch (error) {
    console.error('❌ Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while sending OTP'
    });
  }
};

// @desc    Reset password using OTP
// @route   POST /api/auth/reset-password
// @access  Public
exports.resetPassword = async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    const normalizedEmail = String(email || '').trim().toLowerCase();

    if (!normalizedEmail || !otp || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email, OTP, and new password are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    const hashedOtp = crypto
      .createHash('sha256')
      .update(String(otp).trim())
      .digest('hex');

    const user = await User.findOne({
      email: normalizedEmail,
      passwordResetOtp: hashedOtp,
      passwordResetOtpExpires: { $gt: Date.now() }
    }).select('+password +passwordResetOtp +passwordResetOtpExpires');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    user.password = password;
    user.passwordResetOtp = undefined;
    user.passwordResetOtpExpires = undefined;
    await user.save();

    await recordAuditEvent(req, {
      actor: user._id,
      actorName: user.name,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'Password Reset',
      module: 'auth',
      targetType: 'User',
      targetId: String(user._id),
      targetLabel: user.email,
      details: 'Password changed using OTP',
      metadata: { via: 'otp' }
    });

    res.status(200).json({
      success: true,
      message: 'Password changed successfully. You can login with your new password.'
    });
  } catch (error) {
    console.error('❌ Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while changing password'
    });
  }
};

// @desc    Approve a pending user from email link
// @route   GET /api/auth/approve/:token
// @access  Public approval token
exports.approveUser = async (req, res) => {
  try {
    const approvalToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({ approvalToken }).select('+approvalToken');

    if (!user) {
      return res.status(404).send('<h2>Invalid or expired approval link</h2>');
    }

    user.approvalStatus = 'approved';
    user.approvedAt = new Date();
    user.approvedBy = User.getPrimaryAdminEmail();
    user.rejectedAt = undefined;
    user.rejectedBy = undefined;
    user.approvalToken = undefined;
    user.isActive = true;
    await user.save();

    const decisionEmail = await sendAccessDecisionEmail({
      user,
      decision: 'approved'
    });

    await recordAuditEvent(req, {
      actor: null,
      actorName: User.getPrimaryAdminEmail(),
      actorEmail: User.getPrimaryAdminEmail(),
      actorRole: 'system',
      action: 'User Approved',
      module: 'users',
      targetType: 'User',
      targetId: String(user._id),
      targetLabel: user.email,
      details: `Access approved for ${user.email}`,
      metadata: {
        source: 'email-link',
        analystNotified: Boolean(decisionEmail.sent),
        notificationProvider: decisionEmail.provider || 'console-fallback',
        notificationError: decisionEmail.error || ''
      }
    });

    res.status(200).send(`<h2>Access approved</h2><p>${user.email} can now login to MicroSOC.</p>`);
  } catch (error) {
    console.error('❌ Approval error:', error);
    res.status(500).send('<h2>Server error while approving user</h2>');
  }
};

// @desc    Reject a pending user from email link
// @route   GET /api/auth/reject/:token
// @access  Public approval token
exports.rejectUser = async (req, res) => {
  try {
    const approvalToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({ approvalToken }).select('+approvalToken');

    if (!user) {
      return res.status(404).send('<h2>Invalid or expired rejection link</h2>');
    }

    user.approvalStatus = 'rejected';
    user.rejectedAt = new Date();
    user.rejectedBy = User.getPrimaryAdminEmail();
    user.approvedAt = undefined;
    user.approvedBy = undefined;
    user.approvalToken = undefined;
    user.isActive = false;
    await user.save();

    const decisionEmail = await sendAccessDecisionEmail({
      user,
      decision: 'rejected'
    });

    await recordAuditEvent(req, {
      actor: null,
      actorName: User.getPrimaryAdminEmail(),
      actorEmail: User.getPrimaryAdminEmail(),
      actorRole: 'system',
      action: 'User Rejected',
      module: 'users',
      targetType: 'User',
      targetId: String(user._id),
      targetLabel: user.email,
      details: `Access rejected for ${user.email}`,
      metadata: {
        source: 'email-link',
        analystNotified: Boolean(decisionEmail.sent),
        notificationProvider: decisionEmail.provider || 'console-fallback',
        notificationError: decisionEmail.error || ''
      }
    });

    res.status(200).send(`<h2>Access rejected</h2><p>${user.email} cannot login to MicroSOC.</p>`);
  } catch (error) {
    console.error('❌ Rejection error:', error);
    res.status(500).send('<h2>Server error while rejecting user</h2>');
  }
};

// @desc    Get demo credentials
// @route   GET /api/auth/demo
// @access  Public
exports.getDemoCredentials = async (req, res) => {
  try {
    const demoCredentials = User.getAuthorizedAdmins();

    res.status(200).json({
      success: true,
      demoCredentials
    });
  } catch (error) {
    console.error('❌ Get demo credentials error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
