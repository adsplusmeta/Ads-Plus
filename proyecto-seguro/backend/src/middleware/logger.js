const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'api' },
  transports: [
    new DailyRotateFile({
      filename: 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxFiles: '30d',
      maxSize: '20m',
      zippedArchive: true
    }),
    new DailyRotateFile({
      filename: 'logs/combined-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d',
      maxSize: '20m',
      zippedArchive: true
    }),
    // Logs de seguridad se guardan 90 días para auditoría
    new DailyRotateFile({
      filename: 'logs/security-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'warn',
      maxFiles: '90d',
      maxSize: '20m',
      zippedArchive: true
    })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.printf(({ level, message, timestamp, ...meta }) => {
        const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
        return `${timestamp} [${level}] ${message}${metaStr}`;
      })
    )
  }));
}

// Nunca loguear passwords, tokens ni datos de tarjeta
const REDACTED_FIELDS = new Set(['password', 'token', 'secret', 'credit_card', 'cvv', 'ssn']);

const redactSensitiveData = (obj) => {
  if (typeof obj !== 'object' || obj === null) return obj;
  const clean = { ...obj };
  for (const key of Object.keys(clean)) {
    if (REDACTED_FIELDS.has(key.toLowerCase())) {
      clean[key] = '[REDACTED]';
    } else if (typeof clean[key] === 'object') {
      clean[key] = redactSensitiveData(clean[key]);
    }
  }
  return clean;
};

exports.logSecurityEvent = (event, req, details = {}) => {
  logger.warn({
    type: 'SECURITY_EVENT',
    event,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.user?.id,
    url: req.originalUrl,
    method: req.method,
    ...redactSensitiveData(details)
  });
};

exports.requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info({
      type: 'HTTP',
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      ms: Date.now() - start,
      ip: req.ip,
      userId: req.user?.id
    });
  });
  next();
};

module.exports.logger = logger;
