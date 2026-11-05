# Cyber Info – home page di cyber security

Dashboard che raccoglie notizie, advisory, rivendicazioni ransomware e vulnerabilità sfruttate.
Si aggiorna da sola ogni 30 minuti tramite GitHub Actions ed è pubblicata gratis su GitHub Pages.

## Messa online (una volta sola, circa 10 minuti)

1. Su github.com crea un nuovo repository **pubblico** chiamato `cyber-info`.
   GitHub Pages gratuito richiede un repository pubblico. I dati raccolti sono comunque pubblici.
2. Nella pagina del repository vuoto clicca su **uploading an existing file**.
   Trascina tutto il contenuto di questa cartella, **tranne** `github-workflow-update.yml`: le cartelle `data` e `scripts`, `index.html`, `config.json`, `README.md` e `.nojekyll`.
   Poi clicca su **Commit changes**.
   - Se `.nojekyll` non si vede, attiva *Visualizza → Elementi nascosti* in Esplora risorse.
   - Quel file non è indispensabile.
   - Se aggiungi `data.json` sciolto, assicurati che finisca dentro la cartella `data/`.
   - Trascinando la cartella intera la struttura viene mantenuta.
2b. Crea l'aggiornamento automatico:
   - nel repository vai su **Add file → Create new file**;
   - come nome scrivi esattamente `.github/workflows/update.yml`;
   - incolla il contenuto di `github-workflow-update.yml`;
   - clicca su **Commit changes**.
3. Vai in **Settings → Actions → General → Workflow permissions** e seleziona **Read and write permissions**, poi salva.
4. Vai in **Settings → Pages**. Imposta *Source* su *Deploy from a branch*, branch `main`, cartella `/ (root)`, poi salva.
5. Vai in **Actions → Aggiorna dati cyber → Run workflow** per fare subito il primo aggiornamento.
6. Dopo 1–2 minuti la pagina è online su `https://<tuo-utente>.github.io/cyber-info/`.
7. Impostala come home page del browser:
   - Chrome/Edge: *Impostazioni → All'avvio → Apri una pagina specifica*.

## Come vengono seguiti i gruppi criminali

La pagina riconosce automaticamente migliaia di gruppi, combinando tre fonti:

1. **Tutti i gruppi ransomware** tracciati da ransomware.live, con le loro rivendicazioni sui leak site.
2. **Il catalogo MISP dei threat actor** (APT statali e gruppi criminali), con tutti gli alias.
   Per esempio "Fancy Bear", "Sofacy" e "APT28" vengono riconosciuti come lo stesso gruppo.
3. **Una lista manuale** in `config.json` (`extra_actors`) per gli hacktivisti, che i cataloghi spesso non coprono: NoName057(16), Killnet, CARR, Z-Pentest, Handala, ecc.

Ogni notizia viene etichettata con i gruppi citati. Il pannello **Gruppi** mostra quelli più attivi negli ultimi 7 giorni.
Cliccando un gruppo, in tutta la pagina restano solo le notizie e le rivendicazioni che lo riguardano.
I gruppi della `watchlist` compaiono sempre in cima, con una stella.

Alcuni nomi sono anche parole comuni ("Play", "Medusa", "Royal"). Per evitare falsi positivi vengono riconosciuti solo se vicini a parole come "ransomware", "gang" o "gruppo".
Puoi estendere questa lista con `ambiguous_aliases`.

## Personalizzazione

Modifica solo `config.json`:

- `feeds`: aggiungi o togli fonti RSS (nome, url, lingua `it`/`en`, tipo `news`/`advisory`).
- `threat_keywords`: parole che fanno finire una notizia nella colonna "Allerta & rivendicazioni".
- `watchlist`: i gruppi da tenere sempre d'occhio.
- `extra_actors`: aggiungi un nuovo gruppo (nome, tipo, paese, alias) appena compare nelle cronache.
- `highlight_keywords`: parole che marcano una notizia come IT/EU.

## Note

- Le rivendicazioni dei leak site ransomware arrivano da ransomware.live, che le raccoglie in modo sicuro. Non serve visitare i siti .onion.
- Gli hacktivisti come NoName057(16) rivendicano soprattutto su Telegram. Qui li intercetti tramite le notizie che ne parlano (Red Hot Cyber, The Record, ecc.), riconosciute dalle parole chiave.
- In fondo alla pagina compare un avviso se una fonte non risponde. Le altre continuano ad aggiornarsi normalmente.
- Le voci comparse dopo l'ultima visita hanno un bordo blu a sinistra.
