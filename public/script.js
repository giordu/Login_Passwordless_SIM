const $ = id => document.getElementById(id);
//const output = (data) => $("output").textContent = JSON.stringify(data, null, 2);

const bufferDecode = v => {
  v = v.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(v);
  return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
};

document.getElementById('registerBtn').addEventListener('click', async () => {
  const username    = $('username').value.trim();
  const displayName = $('displayName').value.trim();

  try {
    //richiedo le registration options
    const res1 = await fetch('/webauthn/generate-registration-options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName })
    });
    const text1 = await res1.text();

    if (!res1.ok) {
      console.log('Server risponde ' + `${res1.status}`);
      return;
    }
    const options = JSON.parse(text1);

    options.challenge = bufferDecode(options.challenge);
    options.user.id   = bufferDecode(options.user.id);

    const credential = await navigator.credentials.create({ publicKey: options });

    const attestation = {
      id: credential.id,
      rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      type: credential.type,
      response: {
        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
          .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
          .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      }
    };

    // mando al server per la verifica
    const res2 = await fetch('/webauthn/verify-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attestation, username })
    });

    const text2 = await res2.text();

    if (!res2.ok) {
      console.log('Server risponde' + `${res2.status}`);
      return;
    }
    const result2 = JSON.parse(text2);

    // se registrazione OK, passo al login
    if (result2.success) {
      window.location.href = 'login.html';
    }
  } catch (err) {
    console.error(err);
  }
});

//nel caso in cui si è già registrati
document.getElementById('goToLogin').addEventListener('click', async () => {
  window.location.href = 'login.html'
});