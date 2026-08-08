module.exports = function (app) {
  app.get("/", handler.home);
  app.get("/profile", isLoggedIn, handler.profile);
  // Yazma route'u auth middleware'siz.
  app.post("/memos", handler.addMemo);
  // Kimlik parametresi, sahiplik doğrulaması yok → IDOR.
  app.get("/allocations/:userId", isLoggedIn, handler.allocations);
  // Düzeltilmiş sürüm YORUMDA bekliyor — gerçek route korumasız.
  /* app.post("/benefits", isLoggedIn, isAdmin, handler.updateBenefits); */
  app.post("/benefits", isLoggedIn, handler.updateBenefits);
  const q = Model.findOne({ userId: req.params.userId });
};
