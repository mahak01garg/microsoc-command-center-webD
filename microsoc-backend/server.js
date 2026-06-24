const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const http = require('http');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const realtimeHub = require('./utils/realtimeHub');

// =====================
// Create app
// =====================
const app = express();
const server = http.createServer(app);
app.set('etag', false);

// =====================
// CORS (🔥 MUST BE FIRST)
// =====================
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://127.0.0.1:5173',
  'http://localhost:5173',
  process.env.FRONTEND_URL || 'http://localhost:3000'
];

const isLocalDevOrigin = (origin) => {
  try {
    const { hostname } = new URL(origin);
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch (error) {
    return false;
  }
};

app.use(cors({
  origin: function (origin, callback) {
    // Allow Postman / curl (no origin)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin) || isLocalDevOrigin(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 🔥 Handle preflight requests
app.options('*', cors());

// =====================
// Security & Utils
// =====================
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// =====================
// Database Connection
// =====================
const connectDB = async () => {
  try {
    console.log('🔗 Connecting to MongoDB...');
    await mongoose.connect(
      process.env.MONGODB_URI || 'mongodb://localhost:27017/microsoc'
    );

    console.log('✅ MongoDB connected successfully');

    const User = require('./models/User');
    const AuditLog = require('./models/AuditLog');
    await User.syncAdminUsers();

  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
  }
};

// =====================
// Routes
// =====================
app.use('/api/auth', require('./routes/auth'));
app.use('/api/logs', require('./routes/logs'));
app.use('/api/dashboard', require('./routes/dashboard'));
app.use('/api/incidents', require('./routes/incidents'));
app.use('/api/alerts', require('./routes/alerts'));
app.use('/api/users', require('./routes/users'));
app.use('/api/audit-logs', require('./routes/auditLogs'));
app.use('/api/settings', require('./routes/settings'));
app.use('/api/ai', require('./routes/ai'));
app.use('/api/analytics', require('./routes/analytics'));
app.use('/api/threat-intel', require('./routes/threatIntel'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'MicroSOC Backend is running',
    database:
      mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.get('/api/realtime/status', (req, res) => {
  res.json({
    success: true,
    websocketUrl: `ws://localhost:${process.env.PORT || 5001}/ws/threat-feed`,
    sseUrl: `/api/logs/stream`
  });
});

// Demo credentials
app.get('/api/demo-credentials', (req, res) => {
  const User = require('./models/User');
  res.json({
    admins: User.getAuthorizedAdmins(),
    signupDefaultRole: 'analyst'
  });
});

// =====================
// 404 Handler
// =====================
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// =====================
// Start Server
// =====================
const startServer = async () => {
  await connectDB();

  const PORT = process.env.PORT || 5001;
  server.on('upgrade', (req, socket) => {
    if (req.url.startsWith('/ws/threat-feed')) {
      realtimeHub.handleUpgrade(req, socket);
      return;
    }
    socket.destroy();
  });

  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      console.error(`❌ Port ${PORT} is already in use. Stop the old backend process or run with PORT=${Number(PORT) + 1}.`);
      process.exit(1);
    }
    console.error('❌ Server listen error:', error);
    process.exit(1);
  });

  server.listen(PORT, () => {
    console.log('=================================');
    console.log('🚀 MicroSOC Backend Server');
    console.log('=================================');
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️  Database: ${process.env.MONGODB_URI ? 'configured' : 'mongodb://localhost:27017/microsoc'}`);
    console.log('=================================');
  });
};

startServer();
