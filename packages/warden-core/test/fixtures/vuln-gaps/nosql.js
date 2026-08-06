// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
const User = require("./model");

// B6-nosql-where: $where sunucuda JavaScript çalıştırır.
async function search(req) {
  return User.find({ $where: `this.name == '${req.query.name}'` });
}

// B6-nosql-operator: {"$ne": null} ile kimlik doğrulama bypass'ı.
async function login(req) {
  return User.findOne({ email: req.body.email, password: req.body.password });
}

module.exports = { search, login };
