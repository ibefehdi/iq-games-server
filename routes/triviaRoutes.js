const express = require('express');
const router = express.Router();
const triviaController = require('../controllers/triviaController');

router.get('/questions', triviaController.getQuestions);
router.post('/calculate-iq', triviaController.calculateIQ);
router.get('/word-game/challenge', triviaController.getWordChallenge);
router.post('/word-game/verify', triviaController.verifyWord);
router.post('/word-game/calculate-iq', triviaController.calculateWordIQ);
router.get('/pattern-game/patterns', triviaController.getPatterns);
router.post('/pattern-game/calculate-iq', triviaController.calculatePatternIQ);
router.get('/memory-game/initialize', triviaController.initializeGame);
router.post('/memory-game/calculate-iq', triviaController.calculateMemoryIQ);
module.exports = router;