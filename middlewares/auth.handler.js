const boom = require('@hapi/boom');
const { config } = require('../config/config');

function checkApiKey(req, res, next) {
  const apiKey = req.headers['apikey'];
  console.log(apiKey);
  if (apiKey === config.apiKey) {
    next();
  } else {
    next(boom.unauthorized());
  }
}

function checkRole(...roles) {
  return (req, res, next) => {
    const user = req.user;
    console.log('user and roles', user, roles);
    if (roles.includes(user.role)) {
      next();
    } else {
      next(boom.forbidden('This resource is not allowed'));
    }
  };
}

module.exports = { checkApiKey, checkRole };
