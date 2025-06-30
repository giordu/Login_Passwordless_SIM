const express = require('express');
const {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const base64url = require('base64url');
const db = require('../db');
const router = express.Router();
const rpID = 'localhost';

function getOrigin(req) {
  return `${req.protocol}://${req.get('host')}`;
}

router.post('/generate-authentication-options', (req, res) => {

  const { username } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', username, (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: 'Utente non trovato' });
    }

    db.all('SELECT * FROM credentials WHERE userId = ?', user.id, async (e, creds) => {
      if (e) return res.status(500).json({ error: e.message });

      if (!Array.isArray(creds) || creds.length === 0) {
        return res.status(400).json({ error: 'Nessuna credenziale trovata per l\'utente' });
      }

      const allowCredentials = creds
      .filter(c => c.credentialID)
      .map((c, i) => {
        const idBuffer = Buffer.isBuffer(c.credentialID)
          ? c.credentialID
          : Buffer.from(c.credentialID); 

        return {
          id: base64url.encode(idBuffer),
          type: 'public-key'
        };
      });

      let options;
      try {
        options = await generateAuthenticationOptions({
          rpID,
          timeout: 60000,
          allowCredentials,
          userVerification: 'required',
        });
      } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Errore nella generazione delle opzioni' });
      }

      req.session.currentChallenge = options.challenge;

      res.json({
        ...options,
       allowCredentials,
      });
    });
  });
});

router.post('/verify-authentication', async (req, res) => {
  const { assertion, username } = req.body;
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'Challenge mancante nella sessione' });
  }

  try {
    const cred = await new Promise((ok, ko) =>
      db.get(
        'SELECT * FROM credentials WHERE userId = (SELECT id FROM users WHERE username = ?)',
        username,
        (err, row) => (err ? ko(err) : ok(row))
      )
    );

    if (!cred) {
      return res.status(404).json({ error: 'Credenziale non trovata' });
    }

    const expectedOrigin = getOrigin(req);

    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      credential: cred
    });


    //il counter tiene traccia di quante volte ho fatto l'accesso con quella chiave
    const newCounter = verification.authenticationInfo.newCounter;
    
    // Aggiorna il counter nel DB
    await new Promise((ok, ko) =>
      db.run(
        'UPDATE credentials SET counter = ? WHERE credentialID = ?',
        [newCounter, cred.credentialID],
        err => (err ? ko(err) : ok())
      )
    );

    req.session.loggedIn = true;
    req.session.username = username;

    console.log('Login effettutato con successo per utente: ' + username);

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message});
  }
});

module.exports = router;