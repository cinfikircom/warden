// Kullanıcı girdisi sink'e ULAŞIYOR — taint yüksek güven vermeli.
export function silSorgusu(req, res, db) {
  const ad = req.body.name;
  const sorgu = "SELECT * FROM users WHERE name = '" + ad + "'";
  return db.query(sorgu);
}

// Sabit girdi — sink var ama kullanıcı girdisi yok.
export function sabitSorgu(db) {
  const sorgu = "SELECT * FROM users WHERE name = '" + "admin" + "'";
  return db.query(sorgu);
}

// Temizlenmiş: sayıya çevrilmiş girdi injection taşıyamaz.
export function temizSorgu(req, db) {
  const id = parseInt(req.query.id, 10);
  const sorgu = "SELECT * FROM users WHERE id = " + id;
  return db.query(sorgu);
}

// Destructuring ile taint yayılımı.
export function komutCalistir(req, cp) {
  const { cmd } = req.body;
  cp.exec("ls " + cmd);
}
