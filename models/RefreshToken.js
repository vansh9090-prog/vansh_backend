const mongoose = require('mongoose');

const RefreshSchema = new mongoose.Schema({
  token_hash: { type: String, required: true },
  player_uid: { type: String, required: true, index: true },
  device_id: { type: String },
  revoked: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('RefreshToken', RefreshSchema);
