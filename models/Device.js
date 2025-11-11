const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  device_id: { type: String, required: true, index: true },
  player_uid: { type: String, required: true, index: true },
  public_key_pem: { type: String, required: true },
  encrypted_blob: { type: Object, default: {} },
  last_seen: { type: Date, default: Date.now },
  created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Device', DeviceSchema);
