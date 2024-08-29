# Why?

> Mettendo caso che alice entri in un gruppo sicuro e riceva l'albero delle chiavi pubbliche, come fa ad essere sicura che queste chiavi non siano controllate da un attaccante? 

> Come fa ad essere sicura su chi sono i partecipanti del gruppo? Può un attaccante essere nel gruppo senza che lei lo sappia? Bob è davvero Bob o è qualcun'altro?

**TreeSync** punta a risolvere questi problemi andando ad autenticare gli stati del TreeKEM. Nello specifico:
- autentica tutte le chiavi pubbliche
- autenticare i **group membership agreement**
Prima dell'implementazione del TreeSync, MLS era soggetta a molte tipologie di attacchi di tipo Man-In-The-Middle, cosa che attualmente non sono praticabili.
![[treesync_naive.png]]

Qundo un partecipante aggiorna le sue chiavi, firma un nuovo albero
![[treesync_update_naive.png]]
A questo punto la firma di A non è più riconosciuta dato che è stata sovrascritta da C, quindi il sottoalbero Tx non è più autenticato dalla firma di A.
### Attempt 2
Quando un partecipante aggiorna le proprie credenziali allora firma ogni sottoalbero
![[attempt_2.png]]
Questo significherebbe avere per ogni foglia **log(n)** firme.
### Final Attempt
![[final_attempt.png]]
Come descritto dallo standard [[Messaging Layer Security#TreeKEM]] nella descrizione formale dello stato locale di una foglia per ogni nodo dobbiamo conservare un nuovo valore che prende il nome di **parent hash** che verrà firmato con con la propria chiave pubblica.
![[final_attempt_3.png]]

![[final_attempt_4.png]]
Cosa succede quando abbiamo un aggiornamento di credenziali?
![[final_attempt_update.png]]
Quello che viene fatto è aggiornare la catena di hash dal nodo foglia alla radice, quindi abbiamo una complessità di log(n) ma ogni singolo nodo alla fine contiene una sola firma.