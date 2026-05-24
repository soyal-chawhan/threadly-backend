require('dotenv').config();
const admin = require('firebase-admin');
admin.initializeApp({
  credential: admin.credential.cert({
  "type": "service_account",
  "project_id": "threadly-9fcb1",
  "private_key_id": "24a1053d0627bbf416aeaa9d6a0122535d5ffdea",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDc3oEoSDct2jvd\nTO0nHLANlbAXCiSeNaBIxFHg5Qpc7oIlvlP4ND7IsL/k93TjtZE2I0CQo8MagaMt\nP6nR8yP3d5hzLd9Y4pz46DydIcMimHwdJcgncNYnwyLP4ZYc0dCREeuWgs+K96sp\nP/QpwfyyCD/laFzF7Ld9EieIqk9jLk1i+ucHixJAQIOWPRCjO6mErWwFuWcZL3QD\nap/lj3BboU7G/lvDAnTVcmgz1iU5EOJ6fmEEvTfKnxuSFJfb8dxdfCIX5rUZKotw\n6FcAJ8Z7D449aiSdyJR1oIQeCLmLYMF+8jtSTVEKGfjZHw4WSKiCaEvgnsHr/o1m\nvBFYRJEjAgMBAAECggEASWE9PPJdLsUyHXCY2+U6kpDYS5dJmiyL35El+NdvrXdq\nUvrcb/p/n3Klln8mXR7uKzPkGAnoYK6QVZCwrXmfyfB4fE/Rw/iqGUIjHTth1uUd\nWxu512y0IcrBjppOoq2Mox32jO9R38QwIAjI6HS0LTvzapbVN8bRIWL+MngO3w6d\nkAfxtObKrAM8bnsvWNGxC8w748zECHPrx9uszYdvOu2gxpMBQQ5WO3Z0QLcUaBfU\n/O34dXwqosdbGea10U0pgpCy0kiTX+ik2iUZe9E688++QiNxm3uGjb8gD1ngtO8p\nitY8+V3E+LNQLppi1bBD4NaXgAwyrN/G9dCns6xdnQKBgQDw7aw42fV+QargruyZ\nrMACRIJ6YRsjkJ2CZ5HKfCGNetKPc28WyVlMoLmzQZ8m16WMSV3TZTRQhPhnbvAq\n20X07zCKU9Q0ES994E6002vsV4EdsnClq5hO41OxEMNcut1MV9xONx3pInZFYDvY\ndNsSE2U2vrhh08Z+M0vrwxoQ7wKBgQDqr5g54CTk6srASGTWIJR5jLqNeDDl+Kdu\n/4/oCf9XCwGyGlI+nqDAxD93va9GxNZPf7VTsed9iE3WMIlEO9FA7/WeO5HnzYpN\nXnGOjXcjfKzfc7FKbTLsMb8CQJM8sgoypZqWWNaTHRpaNH5ue4/poLwHTddFNd8p\n3ZuMkV+bDQKBgQDW7xFvfnKV+jtZSnRk/EonO7szNiIh7ke2KHNVsru0HdhuhUqb\nh3EU/WXtVyOGYWec6W68wlKTaqy4ia3Ubd3RDvm8zeBHuvUlVNCiXOKw67eSKLh5\n88Viy0bEdfHzbfkyvEcbt+wFKetdJOb+yfEOBSOMXUTccTNpLpYSc/FzHQKBgQCD\noCqbw0hOEBXZVIEhy7IankB/Wfrq8NRPoAyBUyIgGq8/yh14u5VjqG4EZaHp6jpc\n6j60C2LPeGRXjm9eksIhTrSOo9CIlzJLhH3iOxuoDqQSy5uTJ73Y1WnRBJDQCPdJ\nQrJ6QqdOaZM/JpQGuUyU9y6eVh031ygsHfvBEkPx/QKBgG+Za30lVAu/yLXF/sMH\nQhuvW4ZrdAEZb7YXSL1l4ilgozHopUFKhERetPhlip2W3z7I1VLKjYCHy23veJK/\nkl9NLhHinJBXLQPVRD+3ki07TNOVB3n1Dcp2nF3wTGAcBkBACasFuS9Kcf0ZyskM\n7GqFialokLVvihcJFcNcM0a0\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-fbsvc@threadly-9fcb1.iam.gserviceaccount.com",
  "client_id": "109889777090697861596",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40threadly-9fcb1.iam.gserviceaccount.com",
  })
});
const express    = require('express');
const cors       = require('cors');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit  = require('express-rate-limit');
const User       = require('./models/User');
const OTP        = require('./models/OTP');

const app = express();
app.set('trust proxy', 1);

// ── MIDDLEWARE ──────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: [
    'https://threadly-frontend-zeta.vercel.app',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Rate limit OTP routes (max 50 requests per 15 min per IP)
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  trustProxy: true
});

// ── MONGODB ─────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => { console.error('❌ MongoDB error:', err); process.exit(1); });

// ── EMAIL TRANSPORTER ───────────────────────────
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ── HELPERS ─────────────────────────────────────
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}

async function sendOTPEmail(email, otp, purpose) {
  const subject = purpose === 'reset'
    ? 'Threadly — Reset Your Password'
    : 'Threadly — Verify Your Email';

  const label = purpose === 'reset' ? 'reset your password' : 'verify your email';

  await transporter.sendMail({
    from: `"Threadly" <${process.env.SMTP_USER}>`,
    to:   email,
    subject,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:32px;background:#faf9f7;border-radius:16px;border:1px solid #e5e5e5">
        <h2 style="color:#0f0f0f;margin-bottom:8px">&#x25CF; Threadly</h2>
        <p style="color:#6b6b6b;margin-bottom:24px">Use the code below to ${label}. It expires in <strong>10 minutes</strong>.</p>
        <div style="font-size:2.5rem;font-weight:700;letter-spacing:10px;color:#ff5c3a;background:#fff;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;border:1px solid #ffd5cc">
          ${otp}
        </div>
        <p style="color:#a0a0a0;font-size:0.82rem">If you did not request this, ignore this email. Do not share this code with anyone.</p>
      </div>
    `
  });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    req.user = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

//  ROUTES

// POST /api/auth/register
app.post('/api/auth/register', otpLimiter, async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;

    if (!firstName || !username || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });

    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail)
      return res.status(409).json({ error: 'This email is already registered' });

    const existingUsername = await User.findOne({ username: username.toLowerCase() });
    if (existingUsername)
      return res.status(409).json({ error: 'This username is already taken' });

    const passwordHash = await bcrypt.hash(password, 12);

    // Save unverified user
    await User.create({
      firstName, lastName, username: username.toLowerCase(),
      email: email.toLowerCase(), passwordHash, verified: false
    });

    // Create and save OTP
    const otp = generateOTP();
    await OTP.deleteMany({ email: email.toLowerCase(), purpose: 'verify' }); // clear old
    await OTP.create({
      email: email.toLowerCase(), otp, purpose: 'verify',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    await sendOTPEmail(email, otp, 'verify');
    res.json({ message: 'OTP sent to your email. Please verify.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/verify-otp
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await OTP.findOne({ email: email.toLowerCase(), purpose: 'verify' });
    if (!record)                     return res.status(400).json({ error: 'OTP not found or expired' });
    if (new Date() > record.expiresAt) return res.status(400).json({ error: 'OTP has expired' });
    if (record.otp !== otp)          return res.status(400).json({ error: 'Incorrect OTP' });

    await User.findOneAndUpdate({ email: email.toLowerCase() }, { verified: true });
    await OTP.deleteMany({ email: email.toLowerCase(), purpose: 'verify' });

    const user  = await User.findOne({ email: email.toLowerCase() });
    const token = signToken({ id: user._id, email: user.email });

    res.json({
      message: 'Email verified! Account is active.',
      token,
      user: { id: user._id, email: user.email, firstName: user.firstName, username: user.username }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/resend-otp
app.post('/api/auth/resend-otp', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'No account found with this email' });
    if (user.verified) return res.status(400).json({ error: 'Email already verified' });

    const otp = generateOTP();
    await OTP.deleteMany({ email: email.toLowerCase(), purpose: 'verify' });
    await OTP.create({
      email: email.toLowerCase(), otp, purpose: 'verify',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    await sendOTPEmail(email, otp, 'verify');
    res.json({ message: 'OTP resent successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'No account found with this email' });
    if (!user.verified) return res.status(403).json({ error: 'Please verify your email first' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });

    const token = signToken({ id: user._id, email: user.email });
    res.json({
      token,
      user: { id: user._id, email: user.email, firstName: user.firstName, username: user.username }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'No account found with this email' });

    const otp = generateOTP();
    await OTP.deleteMany({ email: email.toLowerCase(), purpose: 'reset' });
    await OTP.create({
      email: email.toLowerCase(), otp, purpose: 'reset',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    await sendOTPEmail(email, otp, 'reset');
    res.json({ message: 'Reset OTP sent to your email' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword)
      return res.status(400).json({ error: 'All fields required' });
    if (newPassword.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const record = await OTP.findOne({ email: email.toLowerCase(), purpose: 'reset' });
    if (!record)                       return res.status(400).json({ error: 'OTP not found or expired' });
    if (new Date() > record.expiresAt) return res.status(400).json({ error: 'OTP has expired' });
    if (record.otp !== otp)            return res.status(400).json({ error: 'Incorrect OTP' });

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await User.findOneAndUpdate({ email: email.toLowerCase() }, { passwordHash });
    await OTP.deleteMany({ email: email.toLowerCase(), purpose: 'reset' });

    res.json({ message: 'Password reset successfully. Please login.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/me  (protected)
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/google
app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken } = req.body;
    const decoded = await admin.auth().verifyIdToken(idToken);

    let user = await User.findOne({ email: decoded.email.toLowerCase() });

    if (!user) {
      // New user — create account automatically
      const username = decoded.email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '');
      user = await User.create({
        firstName:    decoded.name ? decoded.name.split(' ')[0] : 'User',
        lastName:     decoded.name ? decoded.name.split(' ').slice(1).join(' ') : '',
        username:     username + Math.floor(Math.random() * 999),
        email:        decoded.email.toLowerCase(),
        passwordHash: 'google-oauth-' + decoded.uid,
        verified:     true
      });
    }

    const token = signToken({ id: user._id, email: user.email });
    res.json({
      token,
      user: {
        id:        user._id,
        email:     user.email,
        firstName: user.firstName,
        username:  user.username
      }
    });
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(401).json({ error: 'Invalid Google token' });
  }
});

// GET /health
app.get('/health', (req, res) => res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));

// ── START ────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Threadly API running on http://localhost:${PORT}`));
