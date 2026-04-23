// Configuración centralizada de seguridad del frontend.
// Importar desde aquí en lugar de duplicar valores en toda la app.

export const CSP_CONFIG = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],          // nonce se inyecta desde el servidor
    styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https:"],
    fontSrc: ["'self'", "data:"],
    connectSrc: ["'self'", process.env.REACT_APP_API_URL].filter(Boolean),
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    upgradeInsecureRequests: [],
    blockAllMixedContent: []
  }
};

export const SECURITY_CONFIG = {
  // Tokens y sesión
  tokenStorageKey: "app_session",           // key en sessionStorage (nunca localStorage)
  tokenRefreshThreshold: 5 * 60 * 1000,    // refrescar si quedan menos de 5 min

  // Reintentos HTTP
  maxRetries: 3,
  retryDelay: 1000,

  // Contraseñas
  passwordMinLength: 8,
  passwordRegex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,

  // Límites de inputs
  maxInputLength: 1000,
  maxFileSize: 5 * 1024 * 1024,            // 5 MB
  allowedFileTypes: ["image/jpeg", "image/png", "image/webp", "application/pdf"],

  // Protocolos permitidos en URLs
  allowedProtocols: ["http:", "https:"]
};
