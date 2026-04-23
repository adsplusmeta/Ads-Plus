const promClient = require('prom-client');

const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

const httpDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duración de requests HTTP en segundos',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.05, 0.1, 0.3, 0.5, 1, 2, 5],
  registers: [register]
});

const securityEvents = new promClient.Counter({
  name: 'security_events_total',
  help: 'Total de eventos de seguridad',
  labelNames: ['type', 'severity'],
  registers: [register]
});

const authFailures = new promClient.Counter({
  name: 'auth_failures_total',
  help: 'Total de fallos de autenticación',
  labelNames: ['reason'],
  registers: [register]
});

exports.metricsMiddleware = (req, res, next) => {
  const end = httpDuration.startTimer();
  res.on('finish', () => {
    end({
      method: req.method,
      route: req.route?.path || req.path,
      status: res.statusCode
    });
  });
  next();
};

exports.metricsEndpoint = async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
};

exports.trackSecurityEvent = (type, severity = 'medium') => {
  securityEvents.labels(type, severity).inc();
};

exports.trackAuthFailure = (reason) => {
  authFailures.labels(reason).inc();
};
