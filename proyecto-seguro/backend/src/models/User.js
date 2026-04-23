const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const securityConfig = require('../config/security');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email requerido'],
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: 254,
    match: [/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/, 'Formato de email inválido']
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
    match: [/^[a-zA-Z0-9]+$/, 'Solo letras y números']
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false     // nunca devuelve la contraseña en queries (OWASP A02)
  },
  passwordChangedAt: { type: Date, select: false },
  passwordResetToken: { type: String, select: false },
  passwordResetExpires: { type: Date, select: false },

  role: {
    type: String,
    enum: ['user', 'moderator', 'admin'],
    default: 'user'
  },
  active: {
    type: Boolean,
    default: true,
    select: false
  },

  // Lockout por fuerza bruta (OWASP A07)
  loginAttempts: { type: Number, default: 0 },
  lockUntil:     { type: Date },

  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret:  { type: String, select: false }
}, {
  timestamps: true,
  // Nunca exponer password ni datos internos al serializar
  toJSON: {
    transform(doc, ret) {
      delete ret.password;
      delete ret.twoFactorSecret;
      delete ret.__v;
      return ret;
    }
  }
});

// Hash automático antes de guardar (OWASP A02)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, securityConfig.bcrypt.saltRounds);
  if (!this.isNew) this.passwordChangedAt = new Date(Date.now() - 1000);
  next();
});

userSchema.methods.correctPassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.changedPasswordAfter = function (jwtIat) {
  if (!this.passwordChangedAt) return false;
  return Math.floor(this.passwordChangedAt.getTime() / 1000) > jwtIat;
};

userSchema.methods.isLocked = function () {
  return this.lockUntil && this.lockUntil > Date.now();
};

userSchema.methods.incrementLoginAttempts = async function () {
  const { maxAttempts, lockDuration } = securityConfig.accountLockout;
  this.loginAttempts += 1;
  if (this.loginAttempts >= maxAttempts) {
    this.lockUntil = new Date(Date.now() + lockDuration);
    this.loginAttempts = 0;
  }
  return this.save();
};

userSchema.methods.resetLoginAttempts = async function () {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  return this.save();
};

module.exports = mongoose.model('User', userSchema);
