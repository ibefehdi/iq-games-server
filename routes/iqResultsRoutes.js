const express = require('express');
const router = express.Router();
const iqResultController = require('../controllers/iqResultController');

router.get('/iq-results/user/:userId/', iqResultController.getUserIQResults);
router.get('/results/:resultId', iqResultController.getIQResultById);
router.get('/user/:userId/latest-result', iqResultController.getLatestUserIQResult);

module.exports = router;
