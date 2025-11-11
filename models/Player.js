const mongoose = require('mongoose');

const PlayerSchema = new mongoose.Schema({
  player_uid: { type: String, unique: true, required: true },
  email: { type: String, default: null },
  display_name: { type: String },
  gold: { type: Number, default: 0 },
  xp: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Player', PlayerSchema);
