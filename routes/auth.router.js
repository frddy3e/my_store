const express = require('express');
const passport = require('passport');
const jsonwebtoken = require('jsonwebtoken');
const { config } = require('../config/config');

const router = express.Router();
const AuthService = require('../services/auth.service');
const authService = new AuthService();

router.post(
  '/login',
  passport.authenticate('local', { session: false }),
  async (req, res, next) => {
    try {
      const { user } = req;
      const { token, refreshToken } = authService.signToken(user);

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: config.env !== 'development',
        maxAge: 60000 * 60 * 24 * 30,
      });

      res.json({
        message: 'Login success',
        user: req.user,
        token,
      });
    } catch (error) {
      next(error);
    }
  }
);

router.post('/refresh-token', async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;
    const { token, newRefreshToken } = authService.refreshToken(refreshToken);

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: config.env !== 'development',
      maxAge: 60000 * 60 * 24 * 30,
    });

    res.json({
      message: 'Refresh token success',
      token,
    });
  } catch (error) {
    next(error);
  }
});

router.post('/recovery', async (req, res, next) => {
  try {
    const { email } = req.body;
    const rta = await authService.sendRecovery(email);
    res.json(rta);
  } catch (error) {
    next(error);
  }
});

router.post(
  '/change-password',
  // agregar capa de validacion de datos con joi
  async (req, res, next) => {
    try {
      const { token, newPassword } = req.body;
      const rta = await authService.changePassword(token, newPassword);
      res.json(rta);
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
