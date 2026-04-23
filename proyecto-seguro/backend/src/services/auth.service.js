const User = require('../models/User');
const tokenService = require('./token.service');
const { logSecurityEvent } = require('../middleware/logger');

exports.register = async ({ email, username, password }) => {
  // Verificar si email ya existe ANTES de crear — respuesta genérica para evitar enumeración
  const existing = await User.findOne({ $or: [{ email }, { username }] });
  if (existing) {
    // Error genérico: no revelar si fue email o username (OWASP A01)
    throw Object.assign(new Error('Ya existe una cuenta con esos datos.'), { statusCode: 409 });
  }

  const user = await User.create({ email, username, password });
  return user;
};

exports.login = async (email, password, req, res) => {
  const user = await User.findOne({ email }).select('+password +active +loginAttempts +lockUntil');

  // Respuesta idéntica si usuario no existe o contraseña incorrecta — previene enumeración
  if (!user || !user.active) {
    // Delay artificial para timing-safe comparison aunque usuario no exista
    await new Promise((r) => setTimeout(r, 300));
    throw Object.assign(new Error('Email o contraseña incorrectos.'), { statusCode: 401 });
  }

  if (user.isLocked()) {
    logSecurityEvent('LOCKED_ACCOUNT_ACCESS', req, { userId: user._id });
    throw Object.assign(new Error('Cuenta bloqueada temporalmente. Intenta más tarde.'), { statusCode: 423 });
  }

  const isCorrect = await user.correctPassword(password);
  if (!isCorrect) {
    await user.incrementLoginAttempts();
    logSecurityEvent('FAILED_LOGIN', req, { userId: user._id });
    throw Object.assign(new Error('Email o contraseña incorrectos.'), { statusCode: 401 });
  }

  await user.resetLoginAttempts();

  const token = tokenService.signToken(user._id);
  tokenService.sendTokenCookie(res, token);

  logSecurityEvent('SUCCESSFUL_LOGIN', req, { userId: user._id });

  // Sanitizar output — nunca devolver el documento completo
  const { password: _pw, ...safeUser } = user.toJSON();
  return safeUser;
};

exports.logout = (res) => {
  tokenService.clearTokenCookie(res);
};
