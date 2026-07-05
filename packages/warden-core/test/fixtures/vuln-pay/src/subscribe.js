const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Creates a recurring subscription. The failed-renewal flow is never wired up
// (no unpaid-invoice handler, no access suspension). See PAY-11.
async function subscribe(req, res) {
  const sub = await stripe.subscriptions.create({
    customer: req.body.customerId,
    items: [{ price: req.body.priceId }],
    idempotencyKey: req.body.requestId,
  });
  res.json({ id: sub.id });
}

module.exports = { subscribe };
