const crypto = require('crypto');
const { logger, logSecurityEvent } = require('../middleware/logger');
const { trackSecurityEvent } = require('../middleware/metrics');

class IncidentResponse {
  async report(type, severity, req, details = {}) {
    const id = `INC-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const incident = {
      id,
      type,
      severity,
      ip: req?.ip,
      userId: req?.user?.id,
      url: req?.originalUrl,
      method: req?.method,
      details,
      timestamp: new Date().toISOString()
    };

    logger.error({ type: 'INCIDENT', ...incident });
    trackSecurityEvent(type, severity);

    if (severity === 'high' || severity === 'critical') {
      await this.escalate(incident);
    }

    await this.autoRespond(type, req);
    return id;
  }

  async escalate(incident) {
    // Aquí conectar con PagerDuty / Slack / SIEM según infraestructura
    logger.error({ type: 'ESCALATION', incident });
  }

  async autoRespond(type, req) {
    switch (type) {
      case 'BRUTE_FORCE_ATTEMPT':
        await this.blockIP(req.ip, 60 * 60);          // 1 hora
        break;
      case 'SQL_INJECTION_ATTEMPT':
      case 'XSS_ATTEMPT':
        await this.blockIP(req.ip, 24 * 60 * 60);     // 24 horas
        break;
      case 'UNAUTHORIZED_ACCESS':
        if (req?.user?.id) await this.invalidateSessions(req.user.id);
        break;
    }
  }

  async blockIP(ip, durationSeconds) {
    // Guardar en Redis: SET blocked:ip:<ip> 1 EX <durationSeconds>
    logger.warn({ type: 'IP_BLOCKED', ip, durationSeconds });
  }

  async invalidateSessions(userId) {
    // Incrementar una versión de sesión en BD — los tokens emitidos antes quedan inválidos
    logger.warn({ type: 'SESSIONS_INVALIDATED', userId });
  }
}

module.exports = new IncidentResponse();
