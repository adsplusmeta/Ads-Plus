const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const encryptionService = require('./encryption.service');

exports.generateSecret = (email) => {
  const secret = speakeasy.generateSecret({
    name: `${process.env.TWO_FACTOR_APP_NAME || 'App'} (${email})`,
    length: 32
  });
  // Cifrar el secret antes de guardarlo en BD (OWASP A02)
  return {
    otpauthUrl: secret.otpauth_url,
    encryptedSecret: encryptionService.encrypt(secret.base32),
    base32: secret.base32  // solo para mostrar al usuario una vez
  };
};

exports.generateQRCode = async (otpauthUrl) => {
  return QRCode.toDataURL(otpauthUrl);
};

exports.verifyToken = (token, encryptedSecret) => {
  const secret = encryptionService.decrypt(encryptedSecret);
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: token.toString(),
    window: 1   // tolerancia de ±30s — window:2 sería ±60s (demasiado permisivo)
  });
};
