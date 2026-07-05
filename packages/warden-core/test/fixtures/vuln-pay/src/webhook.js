const express = require("express");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const router = express.Router();

// Stripe payment webhook — WRONG on purpose:
//  - reads the signature header but NEVER verifies it (PAY-2)
//  - no event de-duplication (PAY-8)
//  - only the success path is handled (PAY-10)
router.post("/webhooks/stripe", express.json(), async (req, res) => {
  const sig = req.headers["stripe-signature"]; // read but never checked
  const event = req.body; // trusting the raw body directly

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const pi = await stripe.paymentIntents.retrieve(session.payment_intent);
    await fulfillOrder(session.client_reference_id, pi);
  }

  res.sendStatus(200);
});

async function fulfillOrder(orderId) {
  // grant the customer access to what they bought
}

module.exports = router;
