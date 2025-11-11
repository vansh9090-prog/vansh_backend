const express = require('express');
const fetch = require('node-fetch'); // for exchanging code with Google
const jwt = require('jsonwebtoken');
const uuid = require('uuid');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const Player = require('../models/Player');
const Device = require('../models/Device');
const RefreshToken = require('../models/RefreshToken');
const { encryptForClientRSA } = require('../utils/crypto');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_EXPIRES = process.env.ACCESS_EXPIRES || '15m';

// helper
function issueTokens(player_uid, device_id){
  const accessToken = jwt.sign({ player_uid, device_id }, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
  const refreshToken = uuid.v4() + '.' + uuid.v4();
  return { accessToken, refreshToken };
}

/**
 * POST /api/auth/google_exchange
 * body: { code, device_id, public_key_pem } 
 * (client obtains 'code' from Google Sign-In and sends to server)
 */
router.post('/google_exchange', async (req, res) => {
  try {
    const { code, device_id, public_key_pem } = req.body;
    if (!code || !device_id) return res.status(400).json({ error: 'missing' });

    // exchange code for tokens with Google
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenJson = await tokenResp.json();
    if (tokenJson.error) return res.status(400).json({ error: 'google_exchange_failed', detail: tokenJson });

    // id_token contains verified subject info (or verify separately)
    const id_token = tokenJson.id_token;
    // optionally verify id_token using Google public keys - simple libs available; for brevity, decode:
    const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64').toString('utf8'));
    const google_sub = payload.sub;
    const email = payload.email;

    // find or create player
    let player = await Player.findOne({ email });
    if (!player) {
      const player_uid = 'USER_' + uuid.v4().slice(0,8);
      player = new Player({ player_uid, email, display_name: payload.name || player_uid });
      await player.save();
    }

    // If client provided public_key_pem (device registration), register device
    const tokens = issueTokens(player.player_uid, device_id);
    const rhash = await bcrypt.hash(tokens.refreshToken, 10);
    const refreshDoc = new RefreshToken({ token_hash: rhash, player_uid: player.player_uid, device_id });
    await refreshDoc.save();

    let encrypted_blob = null;
    if (public_key_pem) {
      const payloadBlob = JSON.stringify({ access_token: tokens.accessToken, refresh_token: tokens.refreshToken, issued_at: Date.now() });
      const ciphertext = encryptForClientRSA(public_key_pem, payloadBlob);
      encrypted_blob = { ciphertext, alg: 'RSA-OAEP-SHA256' };
      // upsert device
      await Device.findOneAndUpdate({ device_id }, { device_id, player_uid: player.player_uid, public_key_pem, encrypted_blob, last_seen: new Date() }, { upsert: true });
    }

    return res.json({ result: { player_uid: player.player_uid, encrypted_blob }});
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});
