// Validación de variables de entorno requeridas al arranque.
// Falla rápido si el entorno está mal configurado — evita arrancar con defaults inseguros.

const REQUIRED = [
  'DATABASE_URL',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
  'SESSION_SECRET',
  'ALLOWED_ORIGINS'
];

const MIN_LENGTHS = {
  JWT_SECRET: 32,
  ENCRYPTION_KEY: 64,   // 32 bytes en hex = 64 chars
  SESSION_SECRET: 32
};

exports.validateEnvironment = () => {
  const missing = REQUIRED.filter((key) => !process.env[key]);
  if (missing.length) {
    throw new Error(`Variables de entorno faltantes: ${missing.join(', ')}`);
  }

  for (const [key, minLen] of Object.entries(MIN_LENGTHS)) {
    if (process.env[key].length < minLen) {
      throw new Error(`${key} debe tener al menos ${minLen} caracteres`);
    }
  }

  if (process.env.NODE_ENV === 'production' && !process.env.DATABASE_URL.includes('ssl=true')) {
    console.warn('[WARN] DATABASE_URL no incluye ssl=true en producción');
  }
};
