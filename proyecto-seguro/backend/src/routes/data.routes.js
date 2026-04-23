const express = require('express');
const router = express.Router();
const { restrictTo } = require('../middleware/authentication');
const { validate, idValidation, paginationValidation } = require('../middleware/validator');

// Placeholder — reemplazar con los controllers reales de tu dominio
router.get('/', validate(paginationValidation), (req, res) => {
  res.json({ status: 'ok', message: 'Endpoint de datos funcionando.' });
});

router.get('/:id', validate(idValidation), (req, res) => {
  res.json({ status: 'ok', id: req.params.id });
});

module.exports = router;
