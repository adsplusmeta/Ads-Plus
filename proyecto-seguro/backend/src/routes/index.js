const express = require('express');
const router = express.Router();

const authController = require('../controllers/auth.controller');
const { protect, restrictTo } = require('../middleware/authentication');
const { authLimiter, apiLimiter } = require('../middleware/rateLimiter');
const { validate, registerValidation, loginValidation, idValidation } = require('../middleware/validator');
const { getCsrfToken } = require('../middleware/csrf');
const { metricsEndpoint } = require('../middleware/metrics');

// CSRF token (obtener antes de POSTs)
router.get('/csrf-token', getCsrfToken);

// Auth (rate limit estricto — previene fuerza bruta)
router.post('/auth/register', authLimiter, validate(registerValidation), authController.register);
router.post('/auth/login',    authLimiter, validate(loginValidation),    authController.login);
router.post('/auth/logout',   protect,                                    authController.logout);
router.post('/auth/refresh',  authLimiter,                                authController.refresh);

// 2FA
router.post('/auth/2fa/setup',  protect, authController.setup2FA);
router.post('/auth/2fa/verify', protect, authController.verify2FA);

// Métricas (solo acceso interno / admin)
router.get('/metrics', protect, restrictTo('admin'), metricsEndpoint);

// Rutas de datos (rate limit de API)
router.use('/data', apiLimiter, protect, require('./data.routes'));

module.exports = router;
