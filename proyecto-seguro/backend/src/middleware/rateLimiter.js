const rateLimit = require('express-rate-limit');
const securityConfig = require('../config/security');

// Handler compartido para respuestas de rate limit
const rateLimitHandler = (req, res) => {
  res.status(429).json({
    status: 'error',
    message: 'Demasiadas solicitudes. Por favor espera antes de intentar de nuevo.',
    retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
  });
};

// Límite global: 100 req / 15 min por IP
exports.globalLimiter = rateLimit({
  ...securityConfig.rateLimit.global,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler
});

// Límite estricto para auth: 5 intentos / 15 min — previene fuerza bruta (OWASP A07)
exports.authLimiter = rateLimit({
  ...securityConfig.rateLimit.auth,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    // Loguear el intento de fuerza bruta
    const { logSecurityEvent } = require('./logger');
    logSecurityEvent('BRUTE_FORCE_ATTEMPT', req, { endpoint: req.originalUrl });
    rateLimitHandler(req, res);
  }
});

// Límite de API: 60 req / min para endpoints de datos
exports.apiLimiter = rateLimit({
  ...securityConfig.rateLimit.api,
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler
});
