const bcrypt = require('bcryptjs');
const securityConfig = require('../config/security');

// Helpers standalone — el modelo User hace esto automáticamente vía pre-save hook.
// Usar solo cuando se necesita hashear fuera del contexto de Mongoose.
exports.hashPassword = (password) =>
  bcrypt.hash(password, securityConfig.bcrypt.saltRounds);

exports.comparePassword = (candidate, hash) =>
  bcrypt.compare(candidate, hash);
