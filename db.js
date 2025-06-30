
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('webauthn.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, displayName TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, userId TEXT, credentialID BLOB, publicKey BLOB, counter INTEGER, fmt TEXT, aaguid TEXT, FOREIGN KEY(userId) REFERENCES users(id))`);
});
module.exports = db;
