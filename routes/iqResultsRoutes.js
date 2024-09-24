const express = require('express');
const router = express.Router();
const iqResultController = require('../controllers/iqResultController');

router.get('/user/:userId/results', iqResultController.getUserIQResults);
router.get('/results/:resultId', iqResultController.getIQResultById);
router.get('/user/:userId/latest-result', iqResultController.getLatestUserIQResult);

module.exports = router;
