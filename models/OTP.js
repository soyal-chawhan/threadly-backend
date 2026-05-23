const mongoose = require('mongoose');

const OTPSchema = new mongoose.Schema({
  email:     { type: String, required: true },
  otp:       { type: String, required: true },
  purpose:   { type: String, enum: ['verify', 'reset'], required: true },
  expiresAt: { type: Date,   required: true },
  createdAt: { type: Date,   default: Date.now }
});

// Auto delete expired OTPs from DB
OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('OTP', OTPSchema);