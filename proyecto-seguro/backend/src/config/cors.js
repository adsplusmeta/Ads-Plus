const securityConfig = require('./security');

const allowedOrigins = new Set(securityConfig.cors.origins);

const corsOptions = {
  ...securityConfig.cors,
  origin(origin, callback) {
    // Permitir peticiones sin origin (Postman, curl, mobile) solo en desarrollo
    if (!origin && process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    if (allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS: origin bloqueado — ${origin}`));
  }
};

module.exports = corsOptions;
