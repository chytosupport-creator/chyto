const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const Stripe = require("stripe");

const app = express();
app.use(cors());
app.use(express.json());

// --- Firebase Admin init ---
// Set FIREBASE_SERVICE_ACCOUNT_JSON env var in Render to the full JSON
// contents of your Firebase service account key (one line, escaped).
admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  ),
});

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Middleware: verify Firebase ID token sent from the Android app
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
