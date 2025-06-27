const $ = id => document.getElementById(id);

const bufferDecode = (v) => {
  v = v.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(v);
  return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
};

document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = $('username').value.trim();

  try {
    //richiedo le authentication options
    const res1 = await fetch('/webauthn/generate-authentication-options', {
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body:JSON.stringify({username})
    });
    const text1 = await res1.text(); 
  
    if(!res1.ok) {
      output({ error: `Server risponde ${res1.status}`, details: text1 });
      return;
    }
  
    const opts = JSON.parse(text1);
  
    if (!opts.challenge) {
      output({ error: 'challenge mancante' });
      return;
    }

    opts.challenge = bufferDecode(opts.challenge);    
    opts.allowCredentials = opts.allowCredentials.map(c => ({ ...c, id: bufferDecode(c.id) }));

    const assertion = await navigator.credentials.get({ publicKey: opts });
   
    //mando al server per la verifica
    const res2 = await fetch('/webauthn/verify-authentication', {
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body:JSON.stringify({assertion, username})
    });

    const text2 = await res2.text(); 
    if(!res2.ok) {
      output({ error: `Server risponde ${res2.status}`, details: text2 });
      return;
    }
    

    //se autenticazione ok, passo alla dashboard
    if(res2.ok) {
      window.location.href='dashboard.html';
    }
  }catch(err) {
    console.error(err);
    output({ error: err.message });
  }
  });

  //nel caso sia nella pagin di login ma non sono ancora registrata
  document.getElementById('regBtn').addEventListener('click', async () => {
    window.location.href = 'index.html'
  });
 
