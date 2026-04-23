const crypto = require('crypto');
const { timingSafeCompare } = require('../services/encryption.service');

// Generar API key (llamar una vez, guardar el hash en BD)
exports.generateApiKey = () => {
  const raw = crypto.randomBytes(32).toString('hex');
  const hashed = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hashed };  // guardar 'hashed', devolver 'raw' al usuario
};

// Middleware de validación de API key
exports.validateApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ status: 'error', message: 'API key requerida.' });
  }

  const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');

  // Buscar key activa y no vencida
  // Nota: ApiKey debe ser un modelo Mongoose definido en models/ApiKey.js
  const ApiKey = require('../models/ApiKey');
  const validKey = await ApiKey.findOne({
    key: hashedKey,
    active: true,
    expiresAt: { $gt: new Date() }
  });

  if (!validKey) {
    return res.status(401).json({ status: 'error', message: 'API key inválida o vencida.' });
  }

  // Actualizar estadísticas sin bloquear el request
  ApiKey.updateOne({ _id: validKey._id }, {
    $set: { lastUsed: new Date() },
    $inc: { requestCount: 1 }
  }).exec();

  req.apiKey = validKey;
  next();
};
