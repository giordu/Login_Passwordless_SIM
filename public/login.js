const $ = id => document.getElementById(id);

const bufferDecode = (v) => {
  v = v.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(v);
  return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
};

const bufferEncode = (v) => {
  return btoa(
    String.fromCharCode(...new Uint8Array(v)),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = $('username').value.trim();

  try {
    //richiedo le authentication options
    const res1 = await fetch('/webauthn/generate-authentication-options', {
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body:JSON.stringify({username})
    });
    const opts = await res1.json()
  
    if(!res1.ok) {
      console.log('Server risponde ' + `${res1.status}`);
      if(opts.error == 'Utente non trovato') {
        alert('Username non esistente, riprova...')
      }
      return;
    }
  
    if (!opts.challenge) {
      console.log('challenge mancante')
      return;
    }

    opts.challenge = bufferDecode(opts.challenge);    
    opts.allowCredentials = opts.allowCredentials.map(c => ({ ...c, id: bufferDecode(c.id) }));

    const assertion = await navigator.credentials.get({ publicKey: opts})

    //prepara assertion per essere letto ed elaborato da SimpleWebauthn 
    if (assertion.rawId instanceof Uint8Array) {
      assertion.rawId = bufferEncode(assertion.rawId)
    }

    if(assertion.response.authenticatorData instanceof Uint8Array) {
      assertion.response.authenticatorData = bufferEncode(assertion.response.authenticatorData)
    }

    if(assertion.response.clientDataJSON instanceof Uint8Array) {
      assertion.response.clientDataJSON = bufferEncode(assertion.response.clientDataJSON)
    }

    if(assertion.response.signature instanceof Uint8Array) {
      assertion.response.signature = bufferEncode(assertion.response.signature)
    }

    if(assertion.response.userHandle instanceof Uint8Array) {
      assertion.response.userHandle = bufferEncode(assertion.response.userHandle)
    }
   
    //mando al server per la verifica
    const res2 = await fetch('/webauthn/verify-authentication', {
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body:JSON.stringify({assertion, username})
    });

    const text2 = await res2.text(); 
    if(!res2.ok) {
      console.log('Server risponde' + `${res2.status}`);
      return;
    }

    const result2 = JSON.parse(text2)

    //se autenticazione ok, passo alla dashboard
    if(result2.success) {
      window.location.href='dashboard.html';
    }
  }catch(err) {
    console.error(err);
  }
  });

  //nel caso sia nella pagin di login ma non sono ancora registrata
  document.getElementById('regBtn').addEventListener('click', async () => {
    window.location.href = 'index.html'
  });
 
