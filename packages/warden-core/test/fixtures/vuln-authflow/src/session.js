const bcrypt = require("bcrypt-nodejs"); // import var, kullanım YORUMDA

const invalidUserNameError = "Kullanıcı bulunamadı";
const invalidPasswordError = "Parola hatalı";

exports.handleLogin = (req, res) => {
  const { userName, password } = req.body;
  db.findUser(userName, (err, user) => {
    if (!user) return res.render("login", { loginError: invalidUserNameError });
    /* Düzeltme yorumda:
       if (!bcrypt.compareSync(password, user.password)) ... */
    if (user.password !== password) return res.render("login", { loginError: invalidPasswordError });
    // Oturum yenilenmiyor → session fixation.
    req.session.userId = user._id;
    return res.redirect("/dashboard");
  });
};
