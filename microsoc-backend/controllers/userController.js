const User = require('../models/User');
const { recordAuditEvent } = require('../utils/auditLogger');

function sanitizeUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    isActive: user.isActive,
    approvalStatus: user.approvalStatus,
    approvedAt: user.approvedAt,
    approvedBy: user.approvedBy,
    rejectedAt: user.rejectedAt,
    rejectedBy: user.rejectedBy,
    lastLogin: user.lastLogin,
    loginCount: user.loginCount,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find({})
      .sort({ createdAt: -1 })
      .select('-password -approvalToken -passwordResetOtp -passwordResetOtpExpires');

    res.status(200).json({
      success: true,
      users: users.map(sanitizeUser)
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.updateUserAccess = async (req, res) => {
  try {
    const { id } = req.params;
    const { action, role } = req.body;

    const user = await User.findById(id).select('-password -approvalToken -passwordResetOtp -passwordResetOtpExpires');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.role === 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin accounts are protected'
      });
    }

    if (action === 'approve') {
      user.approvalStatus = 'approved';
      user.isActive = true;
      user.approvedAt = new Date();
      user.approvedBy = req.user.email || req.user.id;
      user.rejectedAt = undefined;
      user.rejectedBy = undefined;
    }

    if (action === 'reject') {
      user.approvalStatus = 'rejected';
      user.isActive = false;
      user.rejectedAt = new Date();
      user.rejectedBy = req.user.email || req.user.id;
      user.approvedAt = undefined;
      user.approvedBy = undefined;
    }

    if (action === 'disable') {
      if (user.approvalStatus !== 'approved') {
        return res.status(400).json({
          success: false,
          message: 'Only approved users can be disabled'
        });
      }
      user.isActive = false;
    }

    if (action === 'enable') {
      if (user.approvalStatus !== 'approved') {
        return res.status(400).json({
          success: false,
          message: 'Only approved users can be enabled'
        });
      }
      user.isActive = true;
    }

    await user.save();

    if (role && ['admin', 'analyst', 'viewer'].includes(role)) {
      const previousRole = user.role;
      user.role = role;
      await user.save();
      if (previousRole !== role) {
        await recordAuditEvent(req, {
          action: 'Role Changed',
          module: 'users',
          targetType: 'User',
          targetId: String(user._id),
          targetLabel: user.email,
          details: `Role changed from ${previousRole} to ${role}`,
          metadata: { previousRole, newRole: role }
        });
      }
    }

    const auditActionMap = {
      approve: 'User Approved',
      reject: 'User Rejected',
      disable: 'User Disabled',
      enable: 'User Enabled'
    };

    if (auditActionMap[action]) {
      const auditVerbMap = {
        approve: 'approved',
        reject: 'rejected',
        disable: 'disabled',
        enable: 'enabled'
      };
      await recordAuditEvent(req, {
        action: auditActionMap[action],
        module: 'users',
        targetType: 'User',
        targetId: String(user._id),
        targetLabel: user.email,
        details: `User ${auditVerbMap[action]} by admin`,
        metadata: { approvalStatus: user.approvalStatus, isActive: user.isActive }
      });
    }

    res.status(200).json({
      success: true,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Update user access error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
