const express = require('express');
const router = express.Router();
const triviaController = require('../controllers/triviaController');

router.get('/questions', triviaController.getQuestions);
router.post('/calculate-iq', triviaController.calculateIQ);

module.exports = router;