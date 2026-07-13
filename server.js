const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const Stripe = require("stripe");
const SibApiV3Sdk = require("sib-api-v3-sdk");
const crypto = require("crypto");
const geoip = require("geoip-lite");

const app = express();
app.set("trust proxy", true);
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
// Render's free tier blocks outbound SMTP ports entirely, so nodemailer
// can never connect regardless of host/IPv4/IPv6 config. Brevo uses a
// plain HTTPS API instead, which isn't blocked, and lets us send from our
// own verified Gmail sender address without needing a custom domain.
const brevoClient = SibApiV3Sdk.ApiClient.instance;
brevoClient.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;
const brevoEmailApi = new SibApiV3Sdk.TransactionalEmailsApi();
const MAIL_FROM = process.env.EMAIL_FROM || "chyto.tech.sup@gmail.com";

function emailTemplate(heading, bodyHtml) {
  return `
  <div style="background:#f4f4f5;padding:32px 16px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
    <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
      <div style="background:#0f0f0f;padding:24px 28px;">
        <span style="color:#ffffff;font-size:20px;font-weight:800;letter-spacing:0.5px;">Chyto</span>
      </div>
      <div style="padding:28px;">
        <h2 style="margin:0 0 16px;font-size:19px;color:#0f0f0f;">${heading}</h2>
        <div style="font-size:14px;line-height:1.6;color:#333;">${bodyHtml}</div>
      </div>
      <div style="padding:16px 28px;background:#fafafa;border-top:1px solid #eee;">
        <p style="margin:0;font-size:11px;color:#999;">This is an automated message from Chyto. Please don't reply directly to this email.</p>
      </div>
    </div>
  </div>`;
}

async function sendMail(to, subject, html) {
  try {
    await brevoEmailApi.sendTransacEmail({
      sender: { email: MAIL_FROM, name: "Chyto" },
      to: [{ email: to }],
      subject,
      htmlContent: html,
    });
    return { success: true };
  } catch (err) {
    const msg = err.response?.body?.message || err.message;
    console.error("sendMail error:", msg);
    return { success: false, error: msg };
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

// Called right after a device session is recorded - looks up the caller's
// IP (offline, via geoip-lite) and merges country/region/city/ip into that
// device's entry so LoggedInDevicesScreen can show it.
app.post("/device/geo", verifyFirebaseToken, async (req, res) => {
  const { deviceId } = req.body;
  const userId = req.userId;
  if (!deviceId) return res.status(400).json({ error: "Missing deviceId" });

  try {
    const ip = getClientIp(req);
    const geo = geoip.lookup(ip) || {};
    const update = {
      [`devices.${deviceId}.ip`]: ip,
      [`devices.${deviceId}.country`]: geo.country || "Unknown",
      [`devices.${deviceId}.region`]: geo.region || "Unknown",
      [`devices.${deviceId}.city`]: geo.city || "Unknown",
    };

    const db = admin.firestore();
    await db.collection("users").doc(userId).update(update);

    return res.json({ success: true, ip, ...geo });
  } catch (err) {
    console.error("device/geo error:", err);
    return res.status(500).json({ error: "Could not resolve device location." });
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
      emailTemplate(
        "Verify it's you \u{1F510}",
        `<p>Someone (hopefully you!) asked to change the ${label} on your Chyto account. Here's your one-time code:</p>
         <div style="text-align:center;margin:28px 0;">
           <span style="display:inline-block;background:#0f0f0f;color:#fff;font-size:28px;letter-spacing:6px;font-weight:700;padding:14px 24px;border-radius:10px;">${code}</span>
         </div>
         <p>This code expires in 1 minute. If you didn't request this, no action is needed \u2014 but you may want to secure your account.</p>`
      )
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
          emailTemplate(
            "Security alert \u{1F6A8}",
            `<p>There have been multiple failed attempts to change your ${label} on your Chyto account.</p>
             <p>To protect you, this action has been temporarily locked for <strong>${formatWait(lockMs)}</strong>.</p>
             <p>If this wasn't you, please secure your account immediately.</p>`
          )
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

      const displayName = (userDoc.data()?.legalName) || (userDoc.data()?.preferredName) || "there";

      await sendMail(
        currentEmail,
        "Your Chyto email address was changed",
        emailTemplate(
          "Email address updated \u2705",
          `<p>Hey ${displayName},</p>
           <p>The email on your Chyto account was just changed from this address to <strong>${challenge.newValue}</strong>.</p>
           <p>If you made this change, no action is needed. If you didn't, please contact support immediately \u2014 your account may be compromised.</p>`
        )
      );

      await sendMail(
        challenge.newValue,
        "This is now your Chyto account email",
        emailTemplate(
          "You're all set \u2705",
          `<p>Hey ${displayName},</p>
           <p><strong>${challenge.newValue}</strong> is now the email address for your Chyto account.</p>
           <p>If this wasn't you, please contact support immediately.</p>`
        )
      );
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
// Contact Us ticket -> emails chyto.support@gmail.com
// =====================================================================

app.post("/contact-us", verifyFirebaseToken, async (req, res) => {
  const { subject, body, userEmail } = req.body;
  if (!subject || !body) {
    return res.status(400).json({ error: "Subject and description are required." });
  }

  const referenceId = "CHY-" + Math.floor(100000 + Math.random() * 900000);

  const result = await sendMail(
    "chyto.support@gmail.com",
    `[Chyto Support Ticket ${referenceId}] ${subject}`,
    `<p><strong>From:</strong> ${userEmail || "unknown"}</p>
     <p><strong>Reference ID:</strong> ${referenceId}</p>
     <p><strong>Subject:</strong> ${subject}</p>
     <p><strong>Description:</strong></p>
     <p>${String(body).replace(/</g, "&lt;")}</p>`
  );

  if (!result.success) {
    return res.status(502).json({ error: "Failed to submit ticket: " + result.error });
  }
  return res.json({ success: true, referenceId });
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

    const result = await sendMail(
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

    if (!result.success) {
      return res.status(502).json({ error: "SMTP send failed: " + result.error });
    }
    return res.json({ success: true });
  } catch (err) {
    console.error("send-welcome-email error:", err);
    return res.status(500).json({ error: "Failed to send welcome email: " + err.message });
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
["EMAIL_HOST", "EMAIL_USER", "EMAIL_PASS"].forEach((k) => {
  if (!process.env[k]) console.warn(`WARNING: env var ${k} is not set - outgoing email will fail.`);
});
app.listen(PORT, () => console.log(`Chyto backend listening on port ${PORT}`));
