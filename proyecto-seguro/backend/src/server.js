require('dotenv').config();
const { validateEnvironment } = require('./utils/secrets');
validateEnvironment();  // falla rápido si el entorno está mal configurado

const express = require('express');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const helmetMiddleware = require('./middleware/helmet');
const { globalLimiter } = require('./middleware/rateLimiter');
const { sanitizeInput } = require('./middleware/sanitizer');
const { csrfProtection } = require('./middleware/csrf');
const { requestLogger } = require('./middleware/logger');
const { metricsMiddleware } = require('./middleware/metrics');
const corsOptions = require('./config/cors');
const connectDB = require('./config/database');
const routes = require('./routes');

const app = express();

// 1. Security Headers (OWASP A05)
app.use(helmetMiddleware);

// 2. CORS (OWASP A01)
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// 3. Rate Limiting global (OWASP A04)
app.use('/api/', globalLimiter);

// 4. Body parsing con límites estrictos — previene DoS por payloads gigantes
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// 5. Sanitización de datos (OWASP A03)
app.use(mongoSanitize());   // NoSQL injection
app.use(xss());              // XSS
app.use(hpp());              // HTTP Parameter Pollution
app.use(sanitizeInput);      // sanitización adicional de strings

// 6. CSRF (OWASP A01) — solo para rutas que modifican estado
app.use('/api/', csrfProtection);

// 7. Logging y métricas
app.use(requestLogger);
app.use(metricsMiddleware);
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// 8. Rutas de la API
app.use('/api', routes);

// 9. Health check (sin auth — para load balancers)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 10. Error handler global — nunca exponer stack traces en producción (OWASP A05)
app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  const isDev = process.env.NODE_ENV !== 'production';

  res.status(status).json({
    status: 'error',
    message: err.message || 'Error interno del servidor.',
    ...(isDev && { stack: err.stack })
  });
});

// 11. Ruta 404
app.use((req, res) => {
  res.status(404).json({ status: 'error', message: 'Endpoint no encontrado.' });
});

// Iniciar servidor
const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT} [${process.env.NODE_ENV}]`);
  });
}).catch((err) => {
  console.error('Error al conectar a la base de datos:', err);
  process.exit(1);
});

// Manejo de errores no capturados — cerrar limpiamente
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION:', err);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  process.exit(1);
});

module.exports = app;
