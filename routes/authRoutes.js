const express = require('express');
const router = express.Router();

const { authenticateUser } = require('../middleware/authentication');

const {
  register,
  login,
  fbLogin,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  googleLogin,
} = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/login/facebook', fbLogin);
router.post('/login/google', googleLogin);
router.delete('/logout', authenticateUser, logout);
router.post('/verify-email', verifyEmail);
router.post('/reset-password', resetPassword);
router.post('/forgot-password', forgotPassword);

module.exports = router;
