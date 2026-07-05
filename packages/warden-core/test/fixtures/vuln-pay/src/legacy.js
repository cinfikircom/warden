const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Legacy Charges API — does NOT support 3DS/SCA (fails for EU cards, PSD2 non-compliant) → PAY-12.
async function chargeCard(req, res) {
  const charge = await stripe.charges.create(
    { amount: 2000, currency: "eur", source: req.body.token },
    { idempotencyKey: req.body.orderId },
  );
  res.json({ id: charge.id });
}

module.exports = { chargeCard };
