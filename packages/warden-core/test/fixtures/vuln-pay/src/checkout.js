const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Server-side checkout — several payment-flow mistakes on purpose.
async function createCheckout(req, res) {
  // WRONG (PAY-3): amount taken straight from the client → price tampering.
  const amount = req.body.amount;
  const card_number = req.body.card_number;
  // WRONG (PAY-5): logging raw card data (PAN + CVV).
  console.log("charging card", card_number, "cvv", req.body.cvv);

  // WRONG (PAY-4): no idempotency key → double charge on retry.
  const intent = await stripe.paymentIntents.create({
    amount: amount,
    currency: "try",
  });

  res.json({ client_secret: intent.client_secret });
}

module.exports = { createCheckout };
