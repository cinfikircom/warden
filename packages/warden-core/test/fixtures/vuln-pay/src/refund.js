const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Refund endpoint — WRONG: refund amount comes straight from the client (over-refund /
// refund fraud), with no check that it belongs to the caller or is <= the original charge → PAY-13.
async function refund(req, res) {
  const r = await stripe.refunds.create(
    { payment_intent: req.body.paymentIntentId, amount: req.body.amount },
    { idempotencyKey: req.body.refundId },
  );
  res.json({ id: r.id });
}

module.exports = { refund };
