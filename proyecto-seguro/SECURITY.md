# Security Policy

## Reporte de Vulnerabilidades

Por favor **no** abras un issue público para reportar vulnerabilidades de seguridad.

Envía un correo a: security@tudominio.com  
PGP Key: https://tudominio.com/.well-known/security.txt

Responderemos en menos de 48 horas con un plan de remediación.

---

## Checklist de Deployment Seguro

### Variables de Entorno
- [ ] `JWT_SECRET` ≥ 64 caracteres aleatorios (`openssl rand -hex 32`)
- [ ] `ENCRYPTION_KEY` = exactamente 64 hex chars (`openssl rand -hex 32`)
- [ ] `SESSION_SECRET` ≥ 32 caracteres
- [ ] Ningún `.env` real commiteado al repositorio
- [ ] `NODE_ENV=production` en producción

### Generación de Secretos
```bash
# JWT_SECRET
openssl rand -hex 32

# ENCRYPTION_KEY
openssl rand -hex 32

# SESSION_SECRET
openssl rand -base64 32
```

### Certificados SSL/TLS
- [ ] Certificado válido instalado (Let's Encrypt o CA comercial)
- [ ] Solo TLS 1.2 y 1.3 habilitados
- [ ] HSTS habilitado con `preload`
- [ ] Certificado con menos de 90 días para vencer → renovar

### Base de Datos
- [ ] MongoDB con autenticación habilitada
- [ ] Conexión SSL en producción
- [ ] No expuesta al público (solo red interna Docker)
- [ ] Backups automáticos y cifrados
- [ ] Backup probado con restore exitoso

### Autenticación y Autorización
- [ ] Tokens JWT con expiración corta (15 min)
- [ ] httpOnly cookies para JWT (no localStorage)
- [ ] 2FA disponible para usuarios
- [ ] Account lockout después de 5 intentos fallidos
- [ ] Password hashing con bcrypt (cost factor 12)

### Headers de Seguridad
- [ ] Content-Security-Policy configurado
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] Strict-Transport-Security con includeSubDomains + preload
- [ ] Referrer-Policy: strict-origin-when-cross-origin
- [ ] Permissions-Policy configurado

### Rate Limiting
- [ ] Límite global: 100 req/15min
- [ ] Límite auth: 5 intentos/15min
- [ ] Rate limiting también en Nginx

### OWASP Top 10 Cubierto
| # | Vulnerabilidad | Mitigación implementada |
|---|---|---|
| A01 | Broken Access Control | JWT + RBAC + CSRF + CORS |
| A02 | Cryptographic Failures | AES-256-GCM + bcrypt + TLS 1.3 + HTTPS |
| A03 | Injection | express-validator + mongoSanitize + xss-clean + parameterized queries |
| A04 | Insecure Design | Rate limiting + body size limits + input validation |
| A05 | Security Misconfiguration | Helmet + CSP + error handling seguro |
| A06 | Vulnerable Components | npm audit + Snyk + versiones pinneadas en Docker |
| A07 | Auth Failures | Account lockout + 2FA + tokens cortos + httpOnly cookies |
| A08 | Software Integrity | npm ci + Docker image scanning |
| A09 | Logging Failures | Winston + rotación de logs + security audit logs 90 días |
| A10 | SSRF | Validación de URLs + whitelist de dominios |

### Monitoreo
- [ ] Prometheus scrapeando métricas del backend
- [ ] Grafana con dashboard de seguridad configurado
- [ ] Alertas por: auth failures > 10/min, errores 5xx, tiempo de respuesta > 2s
- [ ] Logs de seguridad revisados regularmente

### Post-Deployment
- [ ] Escaneo de vulnerabilidades con `npm audit` y Snyk
- [ ] Penetration testing (al menos anual)
- [ ] Revisar logs de seguridad a las 24h del deploy
- [ ] Verificar que backups automáticos funcionan

---

## Incidentes de Seguridad

### Clasificación de Severidad
| Severidad | Criterio | Tiempo de respuesta |
|---|---|---|
| Crítica | RCE, acceso a datos de todos los usuarios | < 4 horas |
| Alta | Auth bypass, SQLi, XSS persistente | < 24 horas |
| Media | CSRF, info disclosure limitada | < 72 horas |
| Baja | Misconfiguration menor | < 1 semana |

### Pasos de Respuesta
1. **Detectar** — alertas automáticas o reporte externo
2. **Contener** — bloquear IP / deshabilitar feature / revocar tokens
3. **Investigar** — revisar logs de auditoría en `logs/security-*.log`
4. **Remediar** — patch + deploy
5. **Comunicar** — notificar usuarios afectados si aplica
6. **Post-mortem** — documentar causa raíz y mejoras preventivas
