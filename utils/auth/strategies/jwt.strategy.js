const { Strategy, ExtractJwt } = require('passport-jwt');

const { config } = require('../../../config/config');

const options = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.authJwtSecret,
};

const JwtStrategy = new Strategy(options, async (payload, done) => {
  try {
    console.log('payload', payload);
    done(null, payload);
  } catch (error) {
    done(error);
  }
});

module.exports = JwtStrategy;
