const boom = require('@hapi/boom');
const bcrypt = require('bcrypt');
const jsonwebtoken = require('jsonwebtoken');

const UserService = require('./user.service');
const userService = new UserService();
const { config } = require('../config/config');
const nodemailer = require('nodemailer');

class AuthService {
  async getUser(email, password) {
    const user = await userService.findByEmail(email);
    if (!user) {
      throw boom.unauthorized();
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw boom.unauthorized();
    }

    delete user.dataValues.password;
    delete user.dataValues.recoveryToken;
    return user;
  }

  signToken(user) {
    const payload = {
      sub: user.id,
      role: user.role,
    };

    const token = jsonwebtoken.sign(payload, config.authJwtSecret, {
      expiresIn: '15m',
    });

    const refreshToken = jsonwebtoken.sign(payload, config.authJwtSecret, {
      expiresIn: '1d',
    });

    return { token, refreshToken };
  }

  refreshToken(refreshToken) {
    const { sub, role } = jsonwebtoken.verify(
      refreshToken,
      config.authJwtSecret
    );

    const payload = {
      sub,
      role,
    };

    const token = jsonwebtoken.sign(payload, config.authJwtSecret, {
      expiresIn: '15m',
    });

    const newRefreshToken = jsonwebtoken.sign(payload, config.authJwtSecret, {
      expiresIn: '1d',
    });

    return { token, newRefreshToken };
  }

  async sendRecovery(email, password) {
    const user = await userService.findByEmail(email);
    if (!user) {
      throw boom.unauthorized();
    }

    const payload = {
      sub: user.id,
    };

    const token = jsonwebtoken.sign(payload, config.authJwtSecret, {
      expiresIn: '15m',
    });
    const link = `${config.frontendUrl}/reset-password?token=${token}`;

    await userService.update(user.id, { recoveryToken: token });
    const mail = {
      from: config.smtpUser, // sender address
      to: `${user.email}`, // list of receivers
      subject: 'Email para recuperar contraseña', // Subject line
      //text: 'Hello world?', // plain text body
      html: `<b>Ingresa a este link =>  ${link}</b>`, // html body
    };

    const rta = await this.sendMail(mail);
    return rta;
  }

  async changePassword(token, newPassword) {
    try {
      const payload = jsonwebtoken.verify(token, config.authJwtSecret);
      const user = await userService.findOne(payload.sub);
      if (user.recoveryToken !== token) {
        throw boom.unauthorized();
      }

      const hash = await bcrypt.hash(newPassword, 10);
      await userService.update(user.id, {
        password: hash,
        recoveryToken: null,
      });
      return { message: 'Password changed' };
    } catch (error) {
      throw boom.unauthorized();
    }
  }

  async sendMail(infoMail) {
    const transporter = nodemailer.createTransport({
      host: config.smtpHost,
      secure: true,
      port: config.smtpPort,
      auth: {
        user: config.smtpUser,
        pass: config.smtpPassword,
      },
    });
    await transporter.sendMail(infoMail);
    return { message: 'Email sent' };
  }
}

module.exports = AuthService;
