// Utilidades criptográficas del cliente.
// Usar solo para datos temporales en memoria — no persistas llaves en el cliente.
import CryptoJS from 'crypto-js';

const getKey = () => {
  const key = process.env.REACT_APP_STORAGE_KEY;
  if (!key) throw new Error('REACT_APP_STORAGE_KEY no configurada');
  return key;
};

// sessionStorage cifrado — los tokens JWT van en httpOnly cookies (backend)
export const secureStorage = {
  setItem(key, value) {
    const encrypted = CryptoJS.AES.encrypt(
      JSON.stringify(value),
      getKey()
    ).toString();
    sessionStorage.setItem(key, encrypted);
  },

  getItem(key) {
    const encrypted = sessionStorage.getItem(key);
    if (!encrypted) return null;
    const bytes = CryptoJS.AES.decrypt(encrypted, getKey());
    const text = bytes.toString(CryptoJS.enc.Utf8);
    if (!text) return null;
    return JSON.parse(text);
  },

  removeItem(key) { sessionStorage.removeItem(key); },
  clear()         { sessionStorage.clear(); }
};

// Hash SHA-256 para fingerprinting (no usar para contraseñas — eso es trabajo del backend)
export const hashSHA256 = (data) => {
  return CryptoJS.SHA256(data).toString();
};

// Genera un nonce aleatorio para formularios
export const generateNonce = (length = 16) => {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
};
