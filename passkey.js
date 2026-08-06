const express = require("express");
const admin = require("firebase-admin");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const router = express.Router();

const RP_ID = "chyto.store";
const RP_NAME = "Chyto";
const ORIGIN = ["android:apk-key-hash:85:35:EC:02:47:FC:A7:73:14:B7:C5:07:B3:2F:3C:24:A3:26:FD:31:6D:09:92:45:B6:6E:21:BF:72:A3:E6:6F", "android:apk-key-hash:77:43:36:27:60:FC:76:5C:BF:AE:B7:2E:C1:9F:B1:EF:DE:18:3B:CB:98:3A:57:04:8F:F7:E7:9D:95:C0:7C:F9"];
const CHALLENGE_TTL_MS = 3 * 60 * 1000;

async function verifyAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing auth token" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.userId = decoded.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid auth token" });
  }
}

router.post("/register-options", verifyAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const authUser = await admin.auth().getUser(uid);
    const db = admin.firestore();
    const snap = await db.collection("users").doc(uid).collection("passkeys").get();
    const excludeCredentials = snap.docs.map((d) => ({
      id: d.id,
      transports: d.data().transports || undefined,
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: authUser.email || uid,
      userID: Buffer.from(uid, "utf8"),
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
    });

    await db.collection("users").doc(uid).set(
      { passkeyChallenge: { challenge: options.challenge, expiresAt: Date.now() + CHALLENGE_TTL_MS } },
      { merge: true }
    );

    return res.json(options);
  } catch (err) {
    console.error("register-options error:", err);
    return res.status(500).json({ error: "Could not start passkey registration" });
  }
});

router.post("/register-verify", verifyAuth, async (req, res) => {
  try {
    const uid = req.userId;
    const { response, deviceName } = req.body;
    const db = admin.firestore();
    const userDoc = await db.collection("users").doc(uid).get();
    const challengeData = userDoc.data()?.passkeyChallenge;
    if (!challengeData || challengeData.expiresAt < Date.now()) {
      return res.status(400).json({ error: "Registration expired. Please try again." });
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: "Passkey verification failed" });
    }

    const { credential } = verification.registrationInfo;
    await db.collection("users").doc(uid).collection("passkeys").doc(credential.id).set({
      publicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      transports: credential.transports || [],
      deviceName: deviceName || "Unknown device",
      createdAt: Date.now(),
    });

    await db.collection("users").doc(uid).update({
      passkeyChallenge: admin.firestore.FieldValue.delete(),
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("register-verify error:", err);
    return res.status(500).json({ error: "Passkey registration failed" });
  }
});

router.get("/list", verifyAuth, async (req, res) => {
  try {
    const db = admin.firestore();
    const snap = await db.collection("users").doc(req.userId).collection("passkeys").get();
    const list = snap.docs.map((d) => ({ id: d.id, deviceName: d.data().deviceName, createdAt: d.data().createdAt }));
    return res.json({ passkeys: list });
  } catch (err) {
    return res.status(500).json({ error: "Could not load passkeys" });
  }
});

router.post("/remove", verifyAuth, async (req, res) => {
  try {
    const { credentialId } = req.body;
    if (!credentialId) return res.status(400).json({ error: "Missing credentialId" });
    await admin.firestore().collection("users").doc(req.userId).collection("passkeys").doc(credentialId).delete();
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Could not remove passkey" });
  }
});

router.post("/login-options", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Missing email" });

    const authUser = await admin.auth().getUserByEmail(email).catch(() => null);
    if (!authUser) return res.status(404).json({ error: "No account with this email" });

    const db = admin.firestore();
    const snap = await db.collection("users").doc(authUser.uid).collection("passkeys").get();
    if (snap.empty) return res.status(404).json({ error: "No passkey set up for this account" });

    const allowCredentials = snap.docs.map((d) => ({
      id: d.id,
      transports: d.data().transports || undefined,
    }));

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: "required",
      allowCredentials,
    });

    const sessionId = db.collection("login_challenges").doc().id;
    await db.collection("login_challenges").doc(sessionId).set({
      uid: authUser.uid,
      challenge: options.challenge,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });

    return res.json({ options, sessionId });
  } catch (err) {
    console.error("login-options error:", err);
    return res.status(500).json({ error: "Could not start passkey login" });
  }
});

router.post("/login-verify", async (req, res) => {
  try {
    const { sessionId, response } = req.body;
    if (!sessionId || !response) return res.status(400).json({ error: "Missing sessionId or response" });

    const db = admin.firestore();
    const sessionDoc = await db.collection("login_challenges").doc(sessionId).get();
    const session = sessionDoc.data();
    if (!session || session.expiresAt < Date.now()) {
      return res.status(400).json({ error: "Login session expired. Please try again." });
    }

    const credentialId = response.id;
    const pkDoc = await db.collection("users").doc(session.uid).collection("passkeys").doc(credentialId).get();
    if (!pkDoc.exists) return res.status(400).json({ error: "Passkey not recognized" });
    const pk = pkDoc.data();

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: session.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: credentialId,
        publicKey: Buffer.from(pk.publicKey, "base64url"),
        counter: pk.counter,
        transports: pk.transports || [],
      },
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "Passkey verification failed" });
    }

    await pkDoc.ref.update({ counter: verification.authenticationInfo.newCounter });
    await sessionDoc.ref.delete();

    const customToken = await admin.auth().createCustomToken(session.uid);
    return res.json({ token: customToken });
  } catch (err) {
    console.error("login-verify error:", err);
    return res.status(500).json({ error: "Passkey login failed" });
  }
});

module.exports = router;
