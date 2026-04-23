// Protege contra XSS (OWASP A03:2021).
// Usar en todo contenido dinámico antes de insertar en el DOM.
import DOMPurify from 'dompurify';

// Solo etiquetas seguras y sin atributos peligrosos
const STRICT_CONFIG = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'target', 'rel'],
  ALLOW_DATA_ATTR: false,
  FORCE_BODY: true
};

// Asegurar que los links externos abran con noopener
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    node.setAttribute('rel', 'noopener noreferrer');
    if (node.getAttribute('target') === '_blank') {
      node.setAttribute('target', '_blank');
    }
  }
});

export const sanitizeHTML = (dirty) => {
  if (typeof dirty !== 'string') return '';
  return DOMPurify.sanitize(dirty, STRICT_CONFIG);
};

export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .trim()
    .slice(0, 1000)                          // límite de longitud
    .replace(/[<>]/g, '')                    // eliminar angle brackets
    .replace(/javascript:/gi, '')            // eliminar protocolo peligroso
    .replace(/on\w+\s*=/gi, '');             // eliminar event handlers inline
};

export const sanitizeURL = (url) => {
  if (typeof url !== 'string') return null;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return parsed.href;
  } catch {
    return null;
  }
};

export const sanitizeFilename = (filename) => {
  if (typeof filename !== 'string') return '';
  return filename
    .replace(/[^a-zA-Z0-9._-]/g, '_')       // solo chars seguros
    .replace(/\.{2,}/g, '.')                  // prevenir path traversal
    .slice(0, 255);
};
