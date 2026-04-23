const crypto = require('crypto');
const securityConfig = require('../config/security');

const KEY = Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex');

if (KEY.length !== 32) {
  throw new Error('ENCRYPTION_KEY debe ser exactamente 32 bytes en hex (64 caracteres)');
}

const { algorithm, ivLength, tagLength } = securityConfig.encryption;

// AES-256-GCM: cifrado autenticado — detecta manipulación de datos (OWASP A02)
exports.encrypt = (plaintext) => {
  const iv  = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  // Serializar todo junto: iv:tag:encrypted
  return [
    iv.toString('hex'),
    tag.toString('hex'),
    encrypted.toString('hex')
  ].join(':');
};

exports.decrypt = (payload) => {
  const [ivHex, tagHex, encHex] = payload.split(':');
  if (!ivHex || !tagHex || !encHex) throw new Error('Payload de cifrado inválido');

  const decipher = crypto.createDecipheriv(
    algorithm,
    KEY,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

  return Buffer.concat([
    decipher.update(Buffer.from(encHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
};

exports.hash = (data) => crypto.createHash('sha256').update(data).digest('hex');

exports.generateSecureToken = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

// Comparación en tiempo constante — previene timing attacks
exports.timingSafeCompare = (a, b) => {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
};
