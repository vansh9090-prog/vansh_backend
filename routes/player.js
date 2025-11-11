const express = require('express');
const Player = require('../models/Player');
const { verifyAccessToken } = require('../middleware/auth');
const router = express.Router();

router.get('/profile', verifyAccessToken, async (req,res) => {
  const uid = req.user.player_uid;
  const p = await Player.findOne({ player_uid: uid }).select('player_uid display_name gold xp level');
  if(!p) return res.status(404).json({error:'not_found'});
  res.json({ result: p });
});

router.post('/add_coins', verifyAccessToken, async (req,res) => {
  const uid = req.user.player_uid;
  const coins = parseInt(req.body.coins) || 0;
  const p = await Player.findOneAndUpdate({player_uid:uid}, {$inc:{gold:coins}, $set:{updated_at:new Date()}}, {new:true});
  res.json({ result: { gold: p.gold }});
});

module.exports = router;
