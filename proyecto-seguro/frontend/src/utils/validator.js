// Validación del lado cliente (OWASP A03).
// El backend SIEMPRE re-valida — esto es solo UX defensivo.
import validator from 'validator';
import { SECURITY_CONFIG } from '../config/security.config';

export const validateEmail = (email) => {
  if (typeof email !== 'string') return false;
  return validator.isEmail(email.trim());
};

export const validatePassword = (password) => {
  if (typeof password !== 'string') return false;
  return SECURITY_CONFIG.passwordRegex.test(password);
};

export const getPasswordStrength = (password) => {
  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/\d/.test(password))    score++;
  if (/[@$!%*?&]/.test(password)) score++;
  if (score <= 2) return 'weak';
  if (score <= 4) return 'medium';
  return 'strong';
};

export const validateUsername = (username) => {
  if (typeof username !== 'string') return false;
  return validator.isAlphanumeric(username) &&
    validator.isLength(username, { min: 3, max: 20 });
};

export const validatePhone = (phone) => {
  if (typeof phone !== 'string') return false;
  return validator.isMobilePhone(phone.trim(), 'any', { strictMode: false });
};

export const validateURL = (url) => {
  if (typeof url !== 'string') return false;
  return validator.isURL(url, {
    protocols: ['http', 'https'],
    require_protocol: true
  });
};

export const validateFileUpload = (file) => {
  const errors = [];
  if (!SECURITY_CONFIG.allowedFileTypes.includes(file.type)) {
    errors.push('Tipo de archivo no permitido.');
  }
  if (file.size > SECURITY_CONFIG.maxFileSize) {
    errors.push('El archivo supera el tamaño máximo (5 MB).');
  }
  return { valid: errors.length === 0, errors };
};

export const validateLength = (value, min = 1, max = SECURITY_CONFIG.maxInputLength) => {
  if (typeof value !== 'string') return false;
  return value.length >= min && value.length <= max;
};
