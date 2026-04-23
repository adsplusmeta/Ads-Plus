const { logSecurityEvent } = require('./logger');

// ABAC (Attribute-Based Access Control) para recursos propios (OWASP A01)
// Evita IDOR: un usuario solo puede acceder a sus propios recursos
exports.isOwner = (getResourceUserId) => async (req, res, next) => {
  try {
    const resourceUserId = await getResourceUserId(req);
    const requestUserId = req.user._id.toString();

    if (resourceUserId !== requestUserId && req.user.role !== 'admin') {
      logSecurityEvent('IDOR_ATTEMPT', req, {
        requestedResource: req.originalUrl,
        resourceOwner: resourceUserId,
        requestor: requestUserId
      });
      return res.status(403).json({ status: 'error', message: 'Acceso denegado.' });
    }
    next();
  } catch (err) {
    next(err);
  }
};
