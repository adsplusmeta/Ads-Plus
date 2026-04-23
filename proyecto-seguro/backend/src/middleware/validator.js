const { body, param, query, validationResult } = require('express-validator');
const securityConfig = require('../config/security');

// Wrapper que ejecuta validaciones y retorna errores formateados (OWASP A03)
exports.validate = (validations) => async (req, res, next) => {
  await Promise.all(validations.map((v) => v.run(req)));
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();

  return res.status(400).json({
    status: 'error',
    errors: errors.array().map(({ path, msg }) => ({ field: path, message: msg }))
  });
};

exports.registerValidation = [
  body('email')
    .isEmail().withMessage('Email inválido')
    .normalizeEmail()
    .isLength({ max: 254 }).withMessage('Email demasiado largo'),

  body('password')
    .isLength({ min: securityConfig.passwords.minLength })
    .withMessage(`Mínimo ${securityConfig.passwords.minLength} caracteres`)
    .matches(securityConfig.passwords.regex)
    .withMessage('La contraseña debe tener mayúscula, minúscula, número y caracter especial'),

  body('username')
    .isAlphanumeric().withMessage('Solo letras y números')
    .isLength({ min: 3, max: 20 }).withMessage('Entre 3 y 20 caracteres')
    .trim()
];

exports.loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty().withMessage('Contraseña requerida').isLength({ max: 128 })
];

exports.idValidation = [
  param('id').isMongoId().withMessage('ID inválido')
];

exports.paginationValidation = [
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt()
];
