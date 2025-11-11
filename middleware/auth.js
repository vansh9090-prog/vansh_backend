const jwt = require('jsonwebtoken');
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

function verifyAccessToken(req,res,next){
  const auth = req.headers['authorization'];
  if(!auth) return res.status(401).json({error:'Missing token'});
  const parts = auth.split(' ');
  if(parts.length!==2 || parts[0] !== 'Bearer') return res.status(401).json({error:'Malformed'});
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch(e) {
    return res.status(401).json({error:'Invalid or expired token'});
  }
}
module.exports = { verifyAccessToken };
