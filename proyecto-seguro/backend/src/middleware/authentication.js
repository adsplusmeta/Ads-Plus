const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/User');
const securityConfig = require('../config/security');
const { logSecurityEvent } = require('./logger');

// Verifica JWT y adjunta usuario al request (OWASP A07)
exports.protect = async (req, res, next) => {
  try {
    // Preferir httpOnly cookie sobre header Authorization — más seguro contra XSS
    let token;
    if (req.cookies?.jwt) {
      token = req.cookies.jwt;
    } else if (req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ status: 'error', message: 'No autenticado.' });
    }

    const decoded = await promisify(jwt.verify)(token, securityConfig.jwt.secret, {
      issuer: securityConfig.jwt.issuer,
      algorithms: [securityConfig.jwt.algorithm]
    });

    const user = await User.findById(decoded.sub).select('+active +passwordChangedAt');
    if (!user || !user.active) {
      return res.status(401).json({ status: 'error', message: 'Usuario no encontrado.' });
    }

    // Invalidar tokens emitidos antes del último cambio de contraseña
    if (user.changedPasswordAfter(decoded.iat)) {
      logSecurityEvent('STALE_TOKEN_USED', req, { userId: user._id });
      return res.status(401).json({ status: 'error', message: 'Contraseña cambiada recientemente. Inicia sesión de nuevo.' });
    }

    req.user = user;
    next();
  } catch (err) {
    logSecurityEvent('INVALID_TOKEN', req, { error: err.message });
    return res.status(401).json({ status: 'error', message: 'Token inválido.' });
  }
};

// Autorización por roles (OWASP A01)
exports.restrictTo = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    logSecurityEvent('UNAUTHORIZED_ACCESS', req, {
      userId: req.user._id,
      requiredRoles: roles,
      userRole: req.user.role
    });
    return res.status(403).json({ status: 'error', message: 'Sin permiso para esta acción.' });
  }
  next();
};
