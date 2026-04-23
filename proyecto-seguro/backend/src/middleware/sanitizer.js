const validator = require('validator');

// Palabras clave SQL peligrosas — defensa en profundidad, no reemplaza queries parametrizadas
const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE|GRANT|REVOKE)\b/gi;

const sanitizeValue = (value) => {
  if (typeof value !== 'string') return value;
  return validator.escape(value.trim()).replace(SQL_KEYWORDS, '');
};

const sanitizeObject = (obj) => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeObject);
  const clean = {};
  for (const [key, val] of Object.entries(obj)) {
    clean[key] = typeof val === 'object' ? sanitizeObject(val) : sanitizeValue(val);
  }
  return clean;
};

// Sanitiza body, query y params en cada request (OWASP A03 + A04)
exports.sanitizeInput = (req, res, next) => {
  if (req.body)   req.body   = sanitizeObject(req.body);
  if (req.query)  req.query  = sanitizeObject(req.query);
  if (req.params) req.params = sanitizeObject(req.params);
  next();
};
