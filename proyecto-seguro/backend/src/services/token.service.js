const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const securityConfig = require('../config/security');

const cookieOptions = {
  httpOnly: true,                                              // inaccesible para JS (protege contra XSS)
  secure: process.env.NODE_ENV === 'production',              // solo HTTPS en producción
  sameSite: 'strict',                                         // protege contra CSRF
  maxAge: 7 * 24 * 60 * 60 * 1000                            // 7 días en ms
};

exports.signToken = (userId) => {
  return jwt.sign(
    { sub: userId },
    securityConfig.jwt.secret,
    {
      expiresIn: securityConfig.jwt.expiresIn,
      issuer:    securityConfig.jwt.issuer,
      algorithm: securityConfig.jwt.algorithm
    }
  );
};

exports.sendTokenCookie = (res, token) => {
  res.cookie('jwt', token, cookieOptions);
};

// Invalidar cookie al hacer logout
exports.clearTokenCookie = (res) => {
  res.cookie('jwt', '', { ...cookieOptions, maxAge: 1 });
};

// Tokens de un solo uso para reset de contraseña (OWASP A07)
exports.generateResetToken = () => {
  const raw = crypto.randomBytes(32).toString('hex');
  const hashed = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hashed };
};
