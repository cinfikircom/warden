// Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
const ldap = require("ldapjs");

// B6-ldap-injection: filtre kaçışsız birleştiriliyor → *)(uid=* ile bypass.
function findUser(client, username, cb) {
  client.search("ou=users,dc=example,dc=com", { filter: "(uid=" + username + ")" }, cb);
}

module.exports = { findUser, ldap };
