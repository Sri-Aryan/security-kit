'use strict';

module.exports = {
  port: Number(process.env.PORT) || 3000,
  jwtSecret: process.env.JWT_SECRET || 'sk-demo-jwt-secret-2024',
  DEBUG: true,
};
