const mongoose = require('mongoose');

const connectDB = async () => {
  const uri = process.env.DATABASE_URL;
  if (!uri) throw new Error('DATABASE_URL no configurada');

  await mongoose.connect(uri, {
    ssl: process.env.NODE_ENV === 'production',
    sslValidate: true,
    maxPoolSize: 10,
    minPoolSize: 2,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    // authSource solo en producción con auth habilitado
    ...(process.env.NODE_ENV === 'production' && { authSource: 'admin' })
  });

  // Logging de queries solo en desarrollo
  if (process.env.NODE_ENV === 'development') {
    mongoose.set('debug', true);
  }

  // No crear índices automáticamente en producción (costoso y bloqueante)
  mongoose.set('autoIndex', process.env.NODE_ENV !== 'production');
};

mongoose.connection.on('error', (err) => {
  console.error('MongoDB error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.warn('MongoDB desconectado — reintentando...');
});

module.exports = connectDB;
