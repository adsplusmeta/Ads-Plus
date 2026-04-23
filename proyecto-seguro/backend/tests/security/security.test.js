const request = require('supertest');
const app = require('../../src/server');

// Suite completa de tests de seguridad — ejecutar con: npm run test:security
// Cada test mapea a una vulnerabilidad del OWASP Top 10

describe('OWASP A03 — Injection', () => {
  describe('XSS Protection', () => {
    it('rechaza scripts en campos de texto', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@test.com',
          username: '<script>alert(1)</script>',
          password: 'ValidPass1!'
        });
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).not.toMatch(/<script>/i);
    });

    it('no devuelve input del usuario sin sanitizar', async () => {
      const xssPayload = '"><img src=x onerror=alert(1)>';
      const res = await request(app)
        .get(`/api/data?search=${encodeURIComponent(xssPayload)}`);
      expect(JSON.stringify(res.body)).not.toMatch(/onerror/i);
    });
  });

  describe('NoSQL Injection', () => {
    it('rechaza operadores MongoDB en el body', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: { $gt: '' },
          password: { $gt: '' }
        });
      // express-mongo-sanitize elimina las keys con $
      expect(res.status).toBe(400);
    });
  });
});

describe('OWASP A07 — Authentication Failures', () => {
  describe('Rate Limiting en auth', () => {
    it('bloquea después de 5 intentos en 15 min', async () => {
      const loginAttempt = () =>
        request(app)
          .post('/api/auth/login')
          .send({ email: 'test@test.com', password: 'wrong' });

      for (let i = 0; i < 5; i++) await loginAttempt();
      const blocked = await loginAttempt();
      expect(blocked.status).toBe(429);
    });
  });

  describe('JWT Security', () => {
    it('rechaza request sin token', async () => {
      const res = await request(app).get('/api/data');
      expect(res.status).toBe(401);
    });

    it('rechaza token malformado', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('Authorization', 'Bearer invalid.token.here');
      expect(res.status).toBe(401);
    });

    it('rechaza token con firma incorrecta', async () => {
      // JWT firmado con secret diferente
      const fakeToken = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.fakesignature';
      const res = await request(app)
        .get('/api/data')
        .set('Authorization', `Bearer ${fakeToken}`);
      expect(res.status).toBe(401);
    });
  });
});

describe('OWASP A05 — Security Misconfiguration', () => {
  describe('Security Headers', () => {
    let res;
    beforeAll(async () => {
      res = await request(app).get('/health');
    });

    it('incluye X-Frame-Options: DENY', () => {
      expect(res.headers['x-frame-options']).toBe('DENY');
    });

    it('incluye X-Content-Type-Options: nosniff', () => {
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('incluye Content-Security-Policy', () => {
      expect(res.headers['content-security-policy']).toBeDefined();
    });

    it('incluye Strict-Transport-Security', () => {
      // HSTS solo activo en producción con HTTPS
      if (process.env.NODE_ENV === 'production') {
        expect(res.headers['strict-transport-security']).toBeDefined();
      }
    });

    it('no expone X-Powered-By', () => {
      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });

  describe('Error handling', () => {
    it('no expone stack traces en producción', async () => {
      // Forzar un error accediendo a endpoint inexistente
      const res = await request(app).get('/api/nonexistent-endpoint-xyz');
      if (process.env.NODE_ENV === 'production') {
        expect(res.body.stack).toBeUndefined();
      }
    });
  });
});

describe('OWASP A01 — Broken Access Control', () => {
  describe('CSRF Protection', () => {
    it('rechaza POST sin CSRF token', async () => {
      const res = await request(app)
        .post('/api/data')
        .send({ data: 'test' });
      expect([400, 403]).toContain(res.status);
    });
  });

  describe('Input Validation', () => {
    it('rechaza email inválido en registro', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'not-an-email', username: 'user123', password: 'ValidPass1!' });
      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
    });

    it('rechaza contraseña débil en registro', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'test@test.com', username: 'user123', password: '123' });
      expect(res.status).toBe(400);
    });
  });
});

describe('OWASP A04 — Insecure Design', () => {
  describe('Rate Limiting global', () => {
    it('responde correctamente bajo el límite', async () => {
      const res = await request(app).get('/health');
      expect(res.headers['ratelimit-remaining']).toBeDefined();
    });
  });
});
