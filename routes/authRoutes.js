const express = require("express");
const {
  register,
  login,
  googleAuth,
  googleCallback,
  forgotPassword,
  resetPassword,
  getUserProfile,
  logout,
} = require("../controllers/authController");
const { protect } = require("../middleware/authMiddleware");
const {
  loginRateLimiter,
  createRateLimiter,
} = require("../middleware/rateLimiter");

const router = express.Router();

// Rate limiter for forgot-password requests (prevent email spam)
const forgotPasswordLimiter = createRateLimiter({
  keyPrefix: "rl:forgot-password",
  limits: [
    { type: "ip", capacity: 5, refillRate: 0.0055 }, // 5 burst, 1 every ~3 min
  ],
  identifierExtractor: (req) => ({
    ip: req.ip,
    identifier: req.body?.email ? req.body.email.trim().toLowerCase() : null,
  }),
});

// Authentication endpoints
router.post("/register", register);
router.post("/login", loginRateLimiter, login);

// Google OAuth 2.0 endpoints
router.get("/google", googleAuth);
router.get("/google/callback", googleCallback);

// Password Reset endpoints
router.post("/forgot-password", forgotPasswordLimiter, forgotPassword);
router.post("/reset-password/:token", resetPassword);

// Session & Profile endpoints
router.post("/logout", logout);
router.get("/profile", protect, getUserProfile);
router.get("/me", protect, getUserProfile);

module.exports = router;