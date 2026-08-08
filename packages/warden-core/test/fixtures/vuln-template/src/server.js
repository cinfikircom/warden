const swig = require("swig");
swig.setDefaults({
  // Düzeltme yorumda bekliyor — gerçek ayar kapalı.
  autoescape: false
  /* autoescape: true */
});
module.exports = swig;
