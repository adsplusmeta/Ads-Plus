const authService = require('../services/auth.service');
const twoFactorService = require('../services/twoFactor.service');
const tokenService = require('../services/token.service');
const User = require('../models/User');

exports.register = async (req, res, next) => {
  try {
    const user = await authService.register(req.body);
    res.status(201).json({ status: 'ok', data: { user } });
  } catch (err) {
    next(err);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await authService.login(email, password, req, res);
    res.json({ status: 'ok', data: { user } });
  } catch (err) {
    next(err);
  }
};

exports.logout = (req, res) => {
  authService.logout(res);
  res.json({ status: 'ok', message: 'Sesión cerrada.' });
};

exports.refresh = async (req, res, next) => {
  try {
    // Reusar el token de la cookie httpOnly para emitir uno nuevo
    const token = tokenService.signToken(req.user._id);
    tokenService.sendTokenCookie(res, token);
    res.json({ status: 'ok' });
  } catch (err) {
    next(err);
  }
};

exports.setup2FA = async (req, res, next) => {
  try {
    const { otpauthUrl, encryptedSecret, base32 } = twoFactorService.generateSecret(req.user.email);
    const qrCode = await twoFactorService.generateQRCode(otpauthUrl);

    // Guardar secret cifrado — no activar 2FA hasta verificar
    await User.findByIdAndUpdate(req.user._id, { twoFactorSecret: encryptedSecret });

    res.json({ status: 'ok', data: { qrCode, manualCode: base32 } });
  } catch (err) {
    next(err);
  }
};

exports.verify2FA = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('+twoFactorSecret');
    const valid = twoFactorService.verifyToken(req.body.token, user.twoFactorSecret);

    if (!valid) {
      return res.status(400).json({ status: 'error', message: 'Código inválido.' });
    }

    await User.findByIdAndUpdate(req.user._id, { twoFactorEnabled: true });
    res.json({ status: 'ok', message: '2FA activado correctamente.' });
  } catch (err) {
    next(err);
  }
};
