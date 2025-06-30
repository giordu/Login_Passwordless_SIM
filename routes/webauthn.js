
const express = require('express');
const { 
  generateRegistrationOptions,
  verifyRegistrationResponse
} = require('@simplewebauthn/server');
const base64url = require('base64url');
const crypto = require('crypto');
const db = require('../db');
const router = express.Router();
const rpID = 'localhost';

function getOrigin(req) {
  return `${req.protocol}://${req.get('host')}`;
}

router.post('/generate-registration-options', (req, res) => {
  const { username, displayName } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', username, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    //const challenge = crypto.randomBytes(32);
    const send = async u => {
      const opts = await generateRegistrationOptions({ 
       rpName: 'WP',
       rpID,
       userName: u.username,
       userID: new Uint8Array(Buffer.from(u.id)),
       challenge: crypto.randomBytes(32),
       userDisplayName: u.displayName,
       timeout: 6000,
       attestationType: 'none',
       authenticatorSelection: {authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'required' },
      });
      req.session.currentChallenge = opts.challenge;
      res.json(opts);
    }

    if (!user)
      { 
        const id = crypto.randomUUID(); 
        db.run('INSERT INTO users VALUES (?, ?, ?)', id, username, displayName, err2 => err2?res.status(500).json({error:err2.message}):send({id,username,displayName})); 
      }
   else send(user);
  });
});

router.post('/verify-registration', async (req, res) => {
  try {
    const { attestation, username } = req.body;
    // await sulla query del DB (promisify o wrapper)
    const user = await new Promise((ok, ko) =>
      db.get('SELECT * FROM users WHERE username = ?', username, (e, u) => e ? ko(e) : ok(u))
    );
    if (!user) return res.status(404).json({ error: 'Utente non trovato' });

    const expectedChallenge = req.session.currentChallenge;
    const expectedOrigin    = getOrigin(req);

    const verification = await verifyRegistrationResponse({
      response:          attestation,
      expectedChallenge,
      expectedOrigin,
      expectedRPID:      rpID,
    });

    if (!verification.verified) {
      return res.status(400).json({ verified: false, info: verification });
    }

    const credentialID = base64url.toBuffer(verification.registrationInfo.credential.id);    
    const credentialPublicKey = verification.registrationInfo.credential.publicKey
    const counter = verification.registrationInfo.credential.counter
    const fmt = verification.registrationInfo.fmt
    const aaguid = verification.registrationInfo.aaguid

    await new Promise((ok, ko) =>
      db.run(
        'INSERT INTO credentials (id, userId, credentialID, publicKey, counter, fmt, aaguid) VALUES (?, ?, ?, ?, ?, ?, ?)',
        crypto.randomUUID(),
        user.id,
        credentialID,
        credentialPublicKey,
        counter,
        fmt,
        aaguid,
        (e) => e ? ko(e) : ok()
      )
    );

    res.json({ success: true });

    console.log('Registrazione effettuata con successo per utente: ' + username);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
