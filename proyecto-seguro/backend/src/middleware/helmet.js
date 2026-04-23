const helmet = require('helmet');
const crypto = require('crypto');

// Genera un nonce por request para CSP — permite scripts inline específicos sin 'unsafe-inline'
const generateNonce = () => crypto.randomBytes(16).toString('base64');

const helmetMiddleware = (req, res, next) => {
  // Adjuntar nonce al objeto res para usarlo en las vistas
  res.locals.nonce = generateNonce();

  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", `'nonce-${res.locals.nonce}'`],
        styleSrc:  ["'self'", `'nonce-${res.locals.nonce}'`],
        imgSrc:    ["'self'", 'data:', 'https:'],
        fontSrc:   ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc:  ["'none'"],
        mediaSrc:   ["'self'"],
        frameSrc:   ["'none'"],
        frameAncestors: ["'none'"],
        baseUri:    ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: []
      }
    },
    // HSTS: fuerza HTTPS por 1 año incluyendo subdominios (OWASP A02)
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    frameguard:        { action: 'deny' },
    noSniff:           true,
    xssFilter:         true,
    referrerPolicy:    { policy: 'strict-origin-when-cross-origin' },
    permissionsPolicy: {
      features: {
        geolocation:    [],
        microphone:     [],
        camera:         [],
        payment:        [],
        usb:            []
      }
    }
  })(req, res, next);
};

module.exports = helmetMiddleware;
