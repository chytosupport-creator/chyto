const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// --- Firebase Admin init ---
admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  ),
});

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- Mailer ---
const mailer = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 587),
  secure: process.env.EMAIL_SECURE === "true",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
const MAIL_FROM = process.env.EMAIL_FROM || process.env.EMAIL_USER;

async function sendMail(to, subject, html) {
  try {
    await mailer.sendMail({ from: MAIL_FROM, to, subject, html });
  } catch (err) {
    console.error("sendMail error:", err.message);
  }
}

// --- Middleware: verify Firebase ID token ---
async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing auth token" });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.userId = decoded.uid;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid auth token" });
  }
}

app.get("/", (req, res) => {
  res.send("Chyto backend is running.");
});

// =====================================================================
// Fraud prevention: one account per device / phone, IP rate-limiting
// =====================================================================

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

// Called BEFORE Firebase account creation - no auth yet.
app.post("/fraud/precheck", async (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: "Missing deviceId" });

  try {
    const db = admin.firestore();
    const ip = getClientIp(req);

    const deviceDoc = await db.collection("device_registry").doc(deviceId).get();
    if (deviceDoc.exists) {
      return res.status(409).json({ error: "An account already exists on this device." });
    }

    const since = Date.now() - 24 * 60 * 60 * 1000;
    const ipLogs = await db.collection("ip_log")
      .where("ip", "==", ip)
      .where("timestamp", ">", since)
      .get();
    if (ipLogs.size >= 3) {
      return res.status(429).json({ error: "Too many accounts created from this network recently. Please try again later." });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("fraud/precheck error:", err);
    return res.status(500).json({ error: "Could not verify registration eligibility." });
  }
});

// Called AFTER Firebase account creation - claims the device/phone/IP for this uid.
app.post("/fraud/claim", verifyFirebaseToken, async (req, res) => {
  const { deviceId, phone } = req.body;
  const userId = req.userId;
  if (!deviceId) return res.status(400).json({ error: "Missing deviceId" });

  try {
    const db = admin.firestore();
    const ip = getClientIp(req);

    if (phone) {
      const phoneRef = db.collection("phone_registry").doc(phone);
      const phoneDoc = await phoneRef.get();
      if (phoneDoc.exists && phoneDoc.data().uid !== userId) {
        return res.status(409).json({ error: "This phone number is already linked to another account." });
      }
      await phoneRef.set({ uid: userId, claimedAt: Date.now() });
    }

    await db.collection("device_registry").doc(deviceId).set({ uid: userId, claimedAt: Date.now() });
    await db.collection("ip_log").add({ ip, uid: userId, timestamp: Date.now() });

    return res.json({ success: true });
  } catch (err) {
    console.error("fraud/claim error:", err);
    return res.status(500).json({ error: "Could not finalize registration." });
  }
});

// Called whenever a phone number is added/changed post-registration.
app.post("/fraud/check-phone", verifyFirebaseToken, async (req, res) => {
  const { phone } = req.body;
  const userId = req.userId;
  if (!phone) return res.status(400).json({ error: "Missing phone" });

  try {
    const db = admin.firestore();
    const phoneRef = db.collection("phone_registry").doc(phone);
    const phoneDoc = await phoneRef.get();
    if (phoneDoc.exists && phoneDoc.data().uid !== userId) {
      return res.status(409).json({ error: "This phone number is already linked to another account." });
    }
    await phoneRef.set({ uid: userId, claimedAt: Date.now() });
    return res.json({ success: true });
  } catch (err) {
    console.error("fraud/check-phone error:", err);
    return res.status(500).json({ error: "Could not verify phone number." });
  }
});

// =====================================================================
// Security code flow (email change / password change)
// =====================================================================

const CODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const CODE_LENGTH = 8;
const CODE_TTL_MS = 60 * 1000; // 1 minute
const MAX_FAILS_BEFORE_LOCK = 5;
const LOCK_STAGES_MS = [
  2 * 60 * 1000,     // 2 min
  30 * 60 * 1000,    // 30 min
  90 * 60 * 1000,    // 1.5 hr
  180 * 60 * 1000,   // 3 hr
  360 * 60 * 1000,   // 6 hr
];

function generateCode() {
  let code = "";
  for (let i = 0; i < CODE_LENGTH; i++) {
    const idx = crypto.randomInt(0, CODE_CHARS.length);
    code += CODE_CHARS[idx];
  }
  return code;
}

function formatWait(ms) {
  const totalMinutes = Math.ceil(ms / 60000);
  if (totalMinutes < 60) return `${totalMinutes} minute(s)`;
  const hours = (totalMinutes / 60).toFixed(1);
  return `${hours} hour(s)`;
}

function isValidType(type) {
  return type === "email" || type === "password";
}

app.post("/security/request-code", verifyFirebaseToken, async (req, res) => {
  const { type, newValue } = req.body;
  const userId = req.userId;

  if (!isValidType(type)) return res.status(400).json({ error: "Invalid type" });
  if (!newValue || typeof newValue !== "string") {
    return res.status(400).json({ error: "Missing newValue" });
  }
  if (type === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newValue)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (type === "password" && newValue.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  try {
    const userRef = admin.firestore().collection("users").doc(userId);
    const userDoc = await userRef.get();
    const existing = (userDoc.data()?.security || {})[type] || {};
    const now = Date.now();

    if (existing.lockUntil && existing.lockUntil > now) {
      return res.status(429).json({
        error: `Too many failed attempts. Please wait ${formatWait(existing.lockUntil - now)} before trying again.`,
      });
    }

    const code = generateCode();
    const challenge = {
      code,
      newValue,
      expiresAt: now + CODE_TTL_MS,
      failCount: existing.failCount || 0,
      stageIndex: existing.stageIndex ?? -1,
      lockUntil: existing.lockUntil || 0,
      redFlagged: existing.redFlagged || false,
    };

    await userRef.update({ [`security.${type}`]: challenge });

    const authUser = await admin.auth().getUser(userId);
    const currentEmail = authUser.email;
    const label = type === "email" ? "email address" : "password";

    await sendMail(
      currentEmail,
      "Your Chyto verification code",
      `<p>Your verification code to change your ${label} is:</p>
       <h2 style="letter-spacing:2px;">${code}</h2>
       <p>This code expires in 1 minute. If you didn't request this, please secure your account.</p>`
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("request-code error:", err);
    return res.status(500).json({ error: "Failed to send code. Please try again." });
  }
});

app.post("/security/verify-code", verifyFirebaseToken, async (req, res) => {
  const { type, code } = req.body;
  const userId = req.userId;

  if (!isValidType(type)) return res.status(400).json({ error: "Invalid type" });
  if (!code || typeof code !== "string") {
    return res.status(400).json({ error: "Missing code" });
  }

  try {
    const userRef = admin.firestore().collection("users").doc(userId);
    const userDoc = await userRef.get();
    const challenge = (userDoc.data()?.security || {})[type];
    const now = Date.now();

    if (!challenge) {
      return res.status(400).json({ error: "No pending request. Please start over." });
    }

    if (challenge.lockUntil && challenge.lockUntil > now) {
      return res.status(429).json({
        error: `Too many failed attempts. Please wait ${formatWait(challenge.lockUntil - now)} before trying again.`,
      });
    }

    if (challenge.expiresAt < now) {
      return res.status(400).json({ error: "Code expired. Please request a new one." });
    }

    const authUser = await admin.auth().getUser(userId);
    const currentEmail = authUser.email;

    if (code !== challenge.code) {
      const newFailCount = (challenge.failCount || 0) + 1;
      let update = { ...challenge, failCount: newFailCount };

      if (newFailCount >= MAX_FAILS_BEFORE_LOCK) {
        const nextStageIndex = Math.min((challenge.stageIndex ?? -1) + 1, LOCK_STAGES_MS.length - 1);
        const lockMs = LOCK_STAGES_MS[nextStageIndex];
        update = {
          ...update,
          failCount: 0,
          stageIndex: nextStageIndex,
          lockUntil: now + lockMs,
          redFlagged: nextStageIndex === LOCK_STAGES_MS.length - 1 ? true : (challenge.redFlagged || false),
        };

        await userRef.update({ [`security.${type}`]: update });

        const label = type === "email" ? "email address" : "password";
        await sendMail(
          currentEmail,
          "Security alert on your Chyto account",
          `<p>There have been multiple failed attempts to change your ${label}.</p>
           <p>Access to this action has been temporarily locked for ${formatWait(lockMs)}.</p>
           <p>If this wasn't you, please secure your account immediately.</p>`
        );

        if (update.redFlagged) {
          console.warn(`RED FLAG: user ${userId} repeatedly failed ${type} change verification.`);
        }
      } else {
        await userRef.update({ [`security.${type}`]: update });
      }

      return res.status(400).json({ error: "Code not correct. Please try again." });
    }

    // Code matched — apply the change
    if (type === "email") {
      await admin.auth().updateUser(userId, { email: challenge.newValue });
      await userRef.set({ email: challenge.newValue }, { merge: true });
    } else {
      await admin.auth().updateUser(userId, { password: challenge.newValue });
    }

    await userRef.update({ [`security.${type}`]: admin.firestore.FieldValue.delete() });

    return res.json({ success: true, newValue: challenge.newValue });
  } catch (err) {
    console.error("verify-code error:", err);
    return res.status(500).json({ error: "Verification failed. Please try again." });
  }
});

// =====================================================================
// Welcome email
// =====================================================================

app.post("/send-welcome-email", verifyFirebaseToken, async (req, res) => {
  const userId = req.userId;
  const name = (req.body?.name || "").trim();

  try {
    const authUser = await admin.auth().getUser(userId);
    const email = authUser.email;
    if (!email) return res.status(400).json({ error: "No email on file" });

    const greetingName = name || "there";

    await sendMail(
      email,
      "Welcome to Chyto!",
      `<p>Hi ${greetingName},</p>
       <p>Welcome to Chyto — glad to have you here. A few things worth knowing:</p>
       <ul>
         <li><strong>Stocks & Investments</strong> — grow your money with simulated market investing right from the app.</li>
         <li><strong>MewMew</strong> — your in-app AI assistant, ready to manage your account, answer questions, and help you navigate the platform any time.</li>
         <li><strong>Move</strong> — send and receive money instantly with other Chyto users.</li>
         <li><strong>Loans</strong> — quick access to short-term loans directly from your account.</li>
         <li><strong>No physical card needed</strong> — your virtual Chytocard works everywhere, so there's no waiting on a card in the mail.</li>
         <li><strong>ChytoPay</strong> — pay seamlessly wherever ChytoPay is accepted.</li>
         <li><strong>Gift Cards</strong> — buy, exchange, and manage gift cards right in the app.</li>
       </ul>
       <p>Glad you're here — enjoy exploring.</p>`
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("send-welcome-email error:", err);
    return res.status(500).json({ error: "Failed to send welcome email." });
  }
});

// =====================================================================
// Existing: collateral card linking
// =====================================================================

app.post("/link-collateral-card", verifyFirebaseToken, async (req, res) => {
  const { paymentMethodId } = req.body;
  const userId = req.userId;

  if (!paymentMethodId) {
    return res.status(400).json({ error: "Missing paymentMethodId" });
  }

  try {
    const pm = await stripe.paymentMethods.retrieve(paymentMethodId);
    if (!pm.card) {
      return res.status(400).json({ error: "Not a card payment method" });
    }

    const userRef = admin.firestore().collection("users").doc(userId);
    const userDoc = await userRef.get();
    let customerId = userDoc.data()?.stripeCustomerId;

    if (!customerId) {
      const customer = await stripe.customers.create({
        metadata: { firebaseUid: userId },
      });
      customerId = customer.id;
      await userRef.set({ stripeCustomerId: customerId }, { merge: true });
    }

    await stripe.paymentMethods.attach(paymentMethodId, { customer: customerId });

    const last4 = pm.card.last4;
    const brand = pm.card.brand;
    const expiry = `${String(pm.card.exp_month).padStart(2, "0")}/${String(pm.card.exp_year).slice(-2)}`;

    await userRef.set(
      {
        collateralCard: {
          last4,
          brand,
          expiry,
          stripePaymentMethodId: paymentMethodId,
          linkedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      },
      { merge: true }
    );

    return res.json({ success: true, last4, brand, expiry });
  } catch (err) {
    console.error("link-collateral-card error:", err);
    return res.status(500).json({ error: err.message || "Card linking failed" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Chyto backend listening on port ${PORT}`));
