import React, { useEffect } from 'react';
import { sanitizeHTML } from './utils/sanitizer';
import { validateEmail, validatePassword } from './utils/validator';
import { secureStorage, generateNonce } from './utils/crypto';

function App() {
  useEffect(() => {
    // Limpiar datos sensibles al cerrar o cambiar de pestaña
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        // Aquí podrías limpiar datos sensibles en memoria
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, []);

  return (
    <div className="App">
      <h1>App Segura</h1>
    </div>
  );
}

export default App;
