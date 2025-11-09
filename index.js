import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// ✅ Paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ MongoDB connect
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error("❌ MONGODB_URI missing in environment");
  process.exit(1);
}
mongoose
  .connect(mongoUri)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err.message));

// ✅ User schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  googleId: String,
  wallet: { type: Number, default: 0 },
  gameUid: { type: String, unique: true },
  gameName: { type: String, default: "BattleZone" },
});

const User = mongoose.model("User", userSchema);

// ✅ Google Login
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post("/auth/google", async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    let user = await User.findOne({ email: payload.email });

    if (!user) {
      const uid = Math.floor(1000000000 + Math.random() * 9000000000).toString();
      user = await User.create({
        name: payload.name,
        email: payload.email,
        googleId: payload.sub,
        wallet: 100,
        gameUid: uid,
        gameName: "BattleZone",
      });
    }

    const authToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ token: authToken, user });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: "Google login failed" });
  }
});

// ✅ Serve signup page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "google-login.html"));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
