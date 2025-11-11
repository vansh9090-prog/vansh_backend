// db.js
const mongoose = require('mongoose');
require('dotenv').config();

const uri = process.env.MONGODB_URI;
mongoose.set('strictQuery', false);
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB connection error', err); process.exit(1); });

module.exports = mongoose;
