const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const AUTHORIZED_ADMINS = [
  {
    name: 'Mahak Garg',
    email: 'mahakgarg197@gmail.com',
    password: 'Ma@010907'
  },
  {
    name: 'Honey Tiwari',
    email: 'honeytiwari11304@gmail.com',
    password: 'Ho@051205'
  }
];

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please provide a name'],
    trim: true,
    maxlength: [50, 'Name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['admin', 'analyst', 'viewer'],
    default: 'analyst'
  },
  avatar: {
    type: String,
    default: 'https://ui-avatars.com/api/?name=User&background=007bff&color=fff'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  approvalToken: {
    type: String,
    select: false
  },
  passwordResetOtp: {
    type: String,
    select: false
  },
  passwordResetOtpExpires: {
    type: Date,
    select: false
  },
  approvalRequestedAt: {
    type: Date
  },
  approvedAt: {
    type: Date
  },
  approvedBy: {
    type: String
  },
  rejectedAt: {
    type: Date
  },
  rejectedBy: {
    type: String
  },
  lastLogin: {
    type: Date
  },
  loginHistory: [{
    timestamp: Date,
    ipAddress: String,
    userAgent: String
  }],
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark'],
      default: 'light'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      }
    }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Remove any existing problematic indexes
UserSchema.pre('save', function(next) {
  // This fixes the duplicate key error for username
  next();
});

// Encrypt password using bcrypt
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }
  
  const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Sign JWT and return
UserSchema.methods.getSignedJwtToken = function() {
  return jwt.sign(
    { id: this._id, role: this.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Match user entered password to hashed password in database
UserSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Check if user is admin
UserSchema.methods.isAdmin = function() {
  return this.role === 'admin';
};

UserSchema.methods.createApprovalToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  this.approvalToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  this.approvalRequestedAt = new Date();
  return token;
};

UserSchema.methods.createPasswordResetOtp = function() {
  const otp = crypto.randomInt(100000, 1000000).toString();
  this.passwordResetOtp = crypto
    .createHash('sha256')
    .update(otp)
    .digest('hex');
  this.passwordResetOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
  return otp;
};

// Virtual for login count
UserSchema.virtual('loginCount').get(function() {
  return this.loginHistory ? this.loginHistory.length : 0;
});

// Method to update login history
UserSchema.methods.updateLoginHistory = function(ipAddress, userAgent) {
  this.lastLogin = new Date();
  this.loginHistory.push({
    timestamp: new Date(),
    ipAddress: ipAddress || 'Unknown',
    userAgent: userAgent || 'Unknown'
  });
  
  // Keep only last 10 login records
  if (this.loginHistory.length > 10) {
    this.loginHistory = this.loginHistory.slice(-10);
  }
  
  return this.save();
};

// Ensure only the two configured admins exist as admins.
UserSchema.statics.syncAdminUsers = async function() {
  try {
    const adminEmails = AUTHORIZED_ADMINS.map((admin) => admin.email);
    
    for (const adminData of AUTHORIZED_ADMINS) {
      try {
        const existingUser = await this.findOne({ email: adminData.email }).select('+password');
        
        if (!existingUser) {
          const user = new this({
            ...adminData,
            role: 'admin',
            approvalStatus: 'approved',
            approvedAt: new Date(),
            approvedBy: 'system',
            isActive: true
          });
          await user.save();
          console.log(`✅ Admin user created: ${user.email}`);
        } else {
          existingUser.name = adminData.name;
          existingUser.role = 'admin';
          existingUser.approvalStatus = 'approved';
          existingUser.approvedAt = existingUser.approvedAt || new Date();
          existingUser.approvedBy = existingUser.approvedBy || 'system';
          existingUser.approvalToken = undefined;
          existingUser.isActive = true;
          await existingUser.save();
          console.log(`✅ Admin user synced: ${adminData.email}`);
        }
      } catch (userError) {
        console.error(`❌ Error syncing admin ${adminData.email}:`, userError.message);
      }
    }

    const result = await this.updateMany(
      { role: 'admin', email: { $nin: adminEmails } },
      { $set: { role: 'analyst' } }
    );
    
    if (result.modifiedCount > 0) {
      console.log(`✅ Demoted ${result.modifiedCount} unauthorized admin account(s) to analyst`);
    }

    console.log('✅ Admin users setup completed');
  } catch (error) {
    console.error('❌ Error in syncAdminUsers:', error.message);
  }
};

UserSchema.statics.getAuthorizedAdmins = function() {
  return AUTHORIZED_ADMINS.map(({ name, email }) => ({ name, email, role: 'admin' }));
};

UserSchema.statics.getPrimaryAdminEmail = function() {
  return AUTHORIZED_ADMINS[0].email;
};

module.exports = mongoose.model('User', UserSchema);
