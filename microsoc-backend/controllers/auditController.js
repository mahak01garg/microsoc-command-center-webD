const AuditLog = require('../models/AuditLog');

function buildQuery(req) {
  const {
    timeRange = '7d',
    module,
    action,
    result,
    search
  } = req.query;

  const now = new Date();
  let startDate;
  switch (timeRange) {
    case '1h':
      startDate = new Date(now.getTime() - (60 * 60 * 1000));
      break;
    case '24h':
      startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
      break;
    case '7d':
      startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
      break;
    case '30d':
      startDate = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
      break;
    case 'all':
      startDate = null;
      break;
    default:
      startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
  }

  const query = {};
  if (startDate) {
    query.timestamp = { $gte: startDate };
  }

  if (module && module !== 'all') query.module = module;
  if (action && action !== 'all') query.action = action;
  if (result && result !== 'all') query.result = result;

  if (search) {
    query.$or = [
      { actorName: { $regex: search, $options: 'i' } },
      { actorEmail: { $regex: search, $options: 'i' } },
      { action: { $regex: search, $options: 'i' } },
      { module: { $regex: search, $options: 'i' } },
      { targetLabel: { $regex: search, $options: 'i' } },
      { details: { $regex: search, $options: 'i' } }
    ];
  }

  return query;
}

exports.getAuditLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 25,
      sortBy = 'timestamp',
      sortOrder = 'desc'
    } = req.query;

    const query = buildQuery(req);
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const limitNumber = Math.min(200, Math.max(1, parseInt(limit, 10) || 25));

    const logs = await AuditLog.find(query)
      .populate('actor', 'name email role avatar')
      .sort(sort)
      .limit(limitNumber)
      .skip((pageNumber - 1) * limitNumber)
      .lean();

    const total = await AuditLog.countDocuments(query);
    const totalPages = Math.ceil(total / limitNumber);
    const stats = await AuditLog.getStatistics(req.query.timeRange || '7d', query);

    res.status(200).json({
      success: true,
      count: logs.length,
      total,
      page: pageNumber,
      totalPages,
      logs: logs.map((log) => ({ ...log, id: String(log._id) })),
      stats
    });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.getAuditLogStats = async (req, res) => {
  try {
    const stats = await AuditLog.getStatistics(req.query.timeRange || '7d', buildQuery(req));
    res.status(200).json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get audit stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};
