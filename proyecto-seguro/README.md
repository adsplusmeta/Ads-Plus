# Proyecto Seguro — Boilerplate Full-Stack con OWASP Top 10

Stack: Node.js + Express + MongoDB + React + Docker + Prometheus/Grafana

## Inicio Rápido

### 1. Clonar y configurar variables de entorno

```bash
# Copiar templates de variables
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env.local

# Generar secretos seguros
echo "JWT_SECRET=$(openssl rand -hex 32)"
echo "ENCRYPTION_KEY=$(openssl rand -hex 32)"
echo "SESSION_SECRET=$(openssl rand -base64 32)"
```

Llenar los valores en `backend/.env` con los secretos generados.

### 2. Instalar dependencias

```bash
cd backend && npm install
cd ../frontend && npm install
```

### 3. Desarrollo local

```bash
# Backend
cd backend && npm run dev

# Frontend (nueva terminal)
cd frontend && npm start
```

### 4. Producción con Docker

```bash
docker-compose -f docker/docker-compose.yml up -d
```

### 5. Tests de seguridad

```bash
cd backend

# Suite de tests de seguridad (OWASP Top 10)
npm run test:security

# Auditoría de dependencias
npm run audit

# Escaneo con Snyk (requiere cuenta)
npm run security:scan
```

## Estructura del Proyecto

```
proyecto-seguro/
├── frontend/          # React app con sanitización y validación cliente
├── backend/           # Express API con capas completas de seguridad
├── database/          # Migraciones y backups cifrados
├── security/          # Certificados, políticas CSP/CORS, audit logs
├── docker/            # Dockerfiles hardened + docker-compose + nginx.conf
├── monitoring/        # Prometheus + Grafana
├── SECURITY.md        # Política de seguridad y checklist de deployment
└── .gitignore         # Excluye .env, certificados, backups, logs
```

## Capas de Seguridad Implementadas

| Capa | Tecnología | Protege contra |
|---|---|---|
| Headers HTTP | Helmet + Nginx | XSS, Clickjacking, MIME sniffing |
| Rate Limiting | express-rate-limit | Fuerza bruta, DoS |
| Autenticación | JWT + httpOnly cookies | XSS robo de tokens |
| CSRF | csrf-csrf (Double Submit) | CSRF |
| Sanitización | mongoSanitize + xss-clean | NoSQL injection, XSS |
| Validación | express-validator | Input malicioso |
| Cifrado | AES-256-GCM | Datos comprometidos en BD |
| Contraseñas | bcrypt (cost 12) | Rainbow tables |
| 2FA | TOTP (speakeasy) | Account takeover |
| Logging | Winston + rotación | Auditoría + forense |
| Monitoreo | Prometheus + Grafana | Detección de anomalías |
| Contenedores | Docker non-root + read-only | Escape de contenedor |

## Generación de Certificados SSL (desarrollo)

```bash
# Auto-firmado para desarrollo — usar Let's Encrypt en producción
openssl req -x509 -newkey rsa:4096 -keyout security/certificates/private-key.pem \
  -out security/certificates/certificate.pem -days 365 -nodes \
  -subj "/CN=localhost"
```
