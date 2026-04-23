const { doubleCsrf } = require('csrf-csrf');

// Double Submit Cookie pattern — más robusto que csurf (deprecado)
// Protege contra CSRF (OWASP A01 - Broken Access Control)
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET,
  cookieName: '__Host-psifi.x-csrf-token',   // __Host- prefix fuerza secure + path=/
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

exports.csrfProtection = doubleCsrfProtection;

exports.getCsrfToken = (req, res) => {
  res.json({ csrfToken: generateToken(req, res) });
};
