// Configuración global de seguridad del servidor.
// Centralizar aquí evita inconsistencias entre middleware.

module.exports = {
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',     // tokens cortos
    refreshExpiresIn: '7d',
    algorithm: 'HS256',
    issuer: 'api.tudominio.com'
  },

  bcrypt: {
    saltRounds: 12   // costo alto: ~250ms en hardware moderno, aceptable para auth
  },

  rateLimit: {
    global: {
      windowMs: 15 * 60 * 1000,
      max: 100
    },
    auth: {
      windowMs: 15 * 60 * 1000,
      max: 5,               // bloquear después de 5 intentos fallidos
      skipSuccessfulRequests: true
    },
    api: {
      windowMs: 60 * 1000,
      max: 60
    }
  },

  cors: {
    origins: (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-Total-Count'],
    maxAge: 600
  },

  session: {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000    // 1 día
    }
  },

  encryption: {
    algorithm: 'aes-256-gcm',
    keyLength: 32,
    ivLength: 16,
    tagLength: 16
  },

  passwords: {
    minLength: 8,
    // Mínimo 1 mayúscula, 1 minúscula, 1 número, 1 caracter especial
    regex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
  },

  // Lockout por fuerza bruta (OWASP A07)
  accountLockout: {
    maxAttempts: 5,
    lockDuration: 15 * 60 * 1000   // 15 minutos
  }
};
