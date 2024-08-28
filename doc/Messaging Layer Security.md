# MLS
## Protocol Overview
MLS consente ai client di formare gruppi all'interno dei quali comunicare in modo sicuro. Ad esempio, un gruppo di utenti può utilizzare i client sui propri telefoni o laptop per unirsi a un gruppo e comunicare tra loro. Un gruppo può essere piccolo come due client (ad esempio, per la semplice messaggistica da persona a persona) o grande come centinaia di migliaia. Un client che fa parte di un gruppo è un membro di quel gruppo. Quando i gruppi cambiano i membri e le proprietà dei gruppi o dei membri, passano da un'epoca all'altra e lo stato crittografico del gruppo si evolve. Il gruppo è rappresentato come un albero, che rappresenta i membri come le foglie di un albero. Viene utilizzato per crittografare in modo efficiente i sottoinsiemi dei membri. Ogni membro ha uno stato chiamato oggetto LeafNode che contiene l'identità, le credenziali e le capacità del cliente. Nell'evoluzione da un'epoca all'altra vengono utilizzati diversi messaggi. 
- Un messaggio **Proposal** propone una modifica da apportare nell'epoca successiva, come l'aggiunta o la rimozione di un membro. 
- Un messaggio di **Commit** dà inizio a una nuova epoca istruendo i membri del gruppo a implementare un insieme di proposte. 
    - Le proposte e i commit sono chiamati collettivamente messaggi *Handshake*. 
- Un **KeyPackage** fornisce le chiavi che possono essere utilizzate per aggiungere il client a un gruppo, tra cui il suo LeafNode e la chiave di firma. 
- Un messaggio di **welcome** fornisce al nuovo membro del gruppo le informazioni per inizializzare il suo stato per l'epoca in cui è stato aggiunto. Naturalmente la maggior parte delle applicazioni (ma non tutte) utilizza MLS per inviare messaggi di gruppo crittografati. 
- Un **Application message** è un messaggio MLS con un payload applicativo arbitrario.
- Infine, un **PublicMessage** contiene un messaggio di Handshake MLS protetto dall'integrità
- **PrivateMessage** contiene un messaggio di Handshake o di applicazione confidenziale e protetto dall'integrità.
## Cryptographic State and Evolution
LO stato crittografico del protocollo MLS è diviso in 3 aree di responsabilità:

![[Cryptographic State and Evolution.png]]
- **Un albero a ratchet** che rappresenta i membri del gruppo, fornendo loro un modo per autenticarsi reciprocamente e crittografare in modo efficiente i messaggi per sottogruppi del gruppo. Ogni epoca ha un albero a ratchet distinto.
- Un **key schedule** che descrive la catena di derivazioni delle chiavi utilizzate per passare da un'epoca all'altra (principalmente utilizzando l'init_secret e l'epoch_secret), così come la derivazione di una varietà di altri segreti.

| Label            | Secret                | Purpose                                                                                             |
| ---------------- | --------------------- | --------------------------------------------------------------------------------------------------- |
| "sender data"    | `sender_data_secret`  | Deriving keys to encrypt sender data                                                                |
| "encryption"     | `encryption_secret`   | is used to initialize the secret tree for the epoch                                                 |
| "exporter"       | `exporter_secret`     | consente ad altri protocolli di sfruttare MLS come scambio generico di chiavi di gruppo autenticate |
| "external"       | `external_secret`     | Deriving the external init key                                                                      |
| "confirm"        | `confirmation_key`    | Computing the confirmation MAC for an epoch                                                         |
| "membership"     | `membership_key`      | Computing the membership MAC for a PublicMessage                                                    |
| "resumption"     | `resumption_psk`      | Proving membership in this epoch (via a PSK injected later)                                         |
| "authentication" | `epoch_authenticator` | Confirming that two clients have the same view of the group                                         |
Ogni nuova epoca viene avviata con un messaggio Commit. Il Commit istruisce i membri esistenti del gruppo ad aggiornare la loro visione dell'albero a ratchet applicando un insieme di Proposals e utilizza l'albero a ratchet aggiornato per distribuire nuova entropia al gruppo. Questa nuova entropia viene fornita solo ai membri della nuova epoca e non ai membri che sono stati rimossi. I Commit mantengono quindi la proprietà che il segreto dell'epoca rimane confidenziale per i membri dell'epoca corrente. Per ogni Commit che aggiunge uno o più membri al gruppo, ci sono uno o più messaggi di Welcome corrispondenti. Ogni messaggio di Welcome fornisce ai nuovi membri le informazioni necessarie per inizializzare la loro visione del piano delle chiavi e dell'albero a ratchet, in modo che queste visioni siano allineate con quelle degli altri membri del gruppo in questa epoca.

## Example Protocol execution
Ci sono 3 operazioni principali nella vita di un gruppo:
- **Aggiunta di un membro**, iniziata da un membro attuale
- **Aggiornamento di una chiave** che rappresenta un membro dell'albero
- **Rimozione di un membro**
Ognuna di queste operazioni viene **proposta** mandando un messaggio del corrispondente tipo (aggiunta, aggiornamento e rimozione). Lo stato del gruppo, tuttavia, non viene modificato fino a quando non viene inviato un messaggio di **Commit** per fornire al gruppo una nuova entropia. Quando un gruppo viene creato per la prima volta, si dice che si trova nell'epoca 0. Successivamente, ogni modifica al gruppo incrementa il numero dell'epoca. In ogni epoca, l'attuale appartenenza al gruppo può essere vista come un array, dove alcune voci possono essere vuote e ogni voce non vuota contiene le credenziali e le chiavi pubbliche di un membro del gruppo.
![[mls-array.png]]
Per convenzione, il creatore del gruppo si trova all'indice 0. Quando si aggiunge un nuovo membro, i suoi dati vengono collocati al primo indice vuoto e, se tutti gli indici sono occupati, estendendo la fine dell'array. Rimuovendo un membro, il suo indice viene svuotato. L'aggiornamento della credenziale o della chiave di un membro modifica il valore memorizzato nel suo indice. L'array dei membri rappresenta uno snapshot dell'appartenenza al gruppo in una particolare epoca e può essere utilizzato per comprendere gli obiettivi di sicurezza di MLS. In ogni epoca, ci aspettiamo che tutti i membri del gruppo siano d'accordo sull'array di membri attuale e che possano inviare e ricevere messaggi di gruppo che saranno visibili solo ai membri attuali.
## Threat Model
Le principali minacce ai messaggi inviati tramite MLS sono rappresentate da network attackers, da server maligni e da membri del gruppo compromessi, il cui stato e le cui chiavi crittografiche sono state ottenute dall'avversario.
## Security Goal
MLS mira a fornire una serie di garanzie di sicurezza, che coprono l'autenticazione e le garanzie di riservatezza in misura diversa in diversi scenari.
- **Message Confidentiality**: Se un client C invia un messaggio M nell'epoca E del gruppo G e C ritiene che i membri di G in E siano C0,...,Cn, allora M è tenuto segreto dall'avversario finché nessuno di questi membri è compromesso.
- **Forward Secrecy**: Se un client C invia (o riceve) un messaggio M nell'epoca E del gruppo G, qualsiasi compromissione di C dopo questo punto non influisce sulla riservatezza di M
- **Message Authentication**: Se un client C accetta un messaggio M nell'epoca E del gruppo G, e se C ritiene che i membri di G in E siano C0,...,Cn, e se nessuno di questi membri è compromesso al momento della ricezione, allora M deve essere stato inviato da uno di questi membri del gruppo per il gruppo G nell'epoca E.
- **Sender Authentication**:Se un client C accetta un messaggio M apparentemente inviato da un client C' nell'epoca E del gruppo G, e se C' non è compromesso al momento della ricezione, allora M deve essere stato inviato da C' nell'epoca E del gruppo G.
- **Membership Agreement**: Se un client C accetta un messaggio M da un client C' nell'epoca E del gruppo G, allora C e C' devono essere d'accordo sull'appartenenza di G a E
- **Post-Remove Security**: Se un client C era membro del gruppo G nell'epoca E e non lo è più nell'epoca E+1, anche se C è stato compromesso nell'epoca <= E, questo non influisce sulla riservatezza dei messaggi inviati nell'epoca >= E+1
- **Post-Update Security**:Se un client C era membro del gruppo G nell'epoca E e ha aggiornato le sue chiavi crittografiche nell'epoca E+1, anche se lo stato precedente di C nelle epoche <= E è stato compromesso, ciò non influisce sulla riservatezza dei messaggi inviati nelle epoche >= E+1
Il primo obiettivo di sicurezza veramente innovativo di MLS è l'accordo di appartenenza, che garantisce che i membri del gruppo siano d'accordo tra loro sull'appartenenza attuale. In pratica, MLS richiede un accordo ancora più forte sull'intera storia di appartenenza del gruppo e sui suoi stati crittografici. Si noti che i protocolli di gruppo attualmente in uso, come Signal Sender Keys, non prevedono un accordo di appartenenza. Gli ultimi due obiettivi riguardano la nozione di sicurezza post-compromissione (PCS) per la messaggistica di gruppo. A differenza della messaggistica a due parti, in cui è necessario spiegare la PCS in termini di situazioni ipotetiche come il furto temporaneo di un dispositivo, i gruppi richiedono una nozione più semplice di recupero dalla compromissione dopo la rimozione. Forse l'obiettivo di sicurezza più importante per MLS è che una volta che un membro è stato rimosso dal gruppo, non può più leggere o scrivere messaggi. Inoltre, MLS fornisce anche una sicurezza post-aggiornamento, proprio come i protocolli a due parti come Signal. Vale la pena notare che la maggior parte dei protocolli di messaggistica di gruppo, tra cui Signal Sender Keys, non forniscono nessuna di queste due proprietà.
## Performance Constraints
Un requisito fondamentale di MLS è che deve supportare il funzionamento asincrono. In altre parole, i membri devono essere in grado di inviare messaggi e apportare modifiche al gruppo senza richiedere che gli altri membri siano online nello stesso momento. Ciò significa che la maggior parte dei classici protocolli di scambio di chiavi di gruppo della letteratura crittografica non sono adatti a MLS. Tuttavia, progettare un protocollo asincrono semplice che soddisfi gli obiettivi di sicurezza sopra descritti non è difficile e tali protocolli sono già stati implementati in Signal, WhatsApp, Matrix, ecc. Il principale vincolo di progettazione è la scalabilità. MLS è pensato per funzionare per gruppi con migliaia di utenti, quindi i protocolli che richiedono calcoli pesanti ai mittenti o ai destinatari o messaggi di grandi dimensioni diventano impraticabili con l'aumentare delle dimensioni del gruppo. La maggior parte dei protocolli di messaggistica di gruppo attualmente in uso scalano linearmente (e a volte quadraticamente) con il numero di utenti e sono in grado di supportare solo gruppi di dimensioni comprese tra 256 e 1024 membri. Il principale collo di bottiglia è rappresentato dal numero di operazioni a chiave pubblica necessarie per l'aggiunta o l'aggiornamento dei membri. Il requisito dichiarato nello statuto dell'MLS è che i requisiti delle risorse debbano scalare linearmente o sub-linearmente con le dimensioni del gruppo.

## Cryptographic Objects
### Cipher Suite
Ogni sessione MLS utilizza una singola suite di cifratura che specifica le seguenti primitive da utilizzare nel calcolo delle chiavi di gruppo:
- HPKE (hybrid public key encryption):
	- A Key Encapsulation Mechanism (KEM)
	- A Key Derivation Function (KDF)
	- An Authenticated Encryption with Associated Data (AEAD) encryption algorithm
- Un algoritmo di hashing
- Algoritmo di message authentication code (MAC)
- Algoritmo di firma
Cipher suites are represented with the CipherSuite type.
### Public Keys
Le chiavi pubbliche HPKE sono valori opachi in un formato definito dal protocollo sottostante.

```
opaque HPKEPublicKey<V>;
```
Signature public keys are likewise represented as opaque values in a format defined by the cipher suite's signature scheme.
```
opaque SignaturePublicKey<V>;
```

### Signing
L'algoritmo di firma specificato nella suite di cifratura di un gruppo è l'algoritmo obbligatorio da utilizzare per firmare i messaggi all'interno del gruppo. DEVE essere lo stesso dell'algoritmo di firma specificato nelle credenziali delle foglie dell'albero (comprese le informazioni dei nodi foglia nei KeyPackages usati per aggiungere nuovi membri). To disambiguate different signatures used in MLS, each signed value is prefixed by a label as shown below:
```
SignWithLabel(SignatureKey, Label, Content) =
    Signature.Sign(SignatureKey, SignContent)

VerifyWithLabel(VerificationKey, Label, Content, SignatureValue) =
    Signature.Verify(VerificationKey, SignContent, SignatureValue)

struct {
    opaque label<V>;
    opaque content<V>;
} SignContent;

```
### Public Key Encryption
As with signing, MLS includes a label and context in encryption operations to avoid confusion between ciphertexts produced for different purposes. Encryption and decryption including this label and context are done as follows:
```
EncryptWithLabel(PublicKey, Label, Context, Plaintext) =
  SealBase(PublicKey, EncryptContext, "", Plaintext)

DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext) =
  OpenBase(KEMOutput, PrivateKey, EncryptContext, "", Ciphertext)

struct {
  opaque label<V>;
  opaque context<V>;
} EncryptContext;

```

### Hash based Identifiers
Alcuni messaggi MLS fanno riferimento ad altri oggetti MLS tramite hash. Ad esempio, i messaggi di benvenuto si riferiscono ai KeyPackage dei membri accolti, mentre i commit si riferiscono alle proposte a cui fanno riferimento. Questi identificatori sono calcolati come segue:

```
opaque HashReference<V>;

HashReference KeyPackageRef;
HashReference ProposalRef;

MakeKeyPackageRef(value)
  = RefHash("MLS 1.0 KeyPackage Reference", value)

MakeProposalRef(value)
  = RefHash("MLS 1.0 Proposal Reference", value)

RefHash(label, value) = Hash(RefHashInput)
```

### Credentials
Ogni membro di un gruppo presenta delle credenziali che forniscono una o più identità del membro e le associa alla sua chiave di firma. Le identità e la chiave di firma sono verificate dal Servizio di autenticazione in uso per un gruppo. Spetta all'applicazione decidere quali identificatori utilizzare a livello di applicazione. Ad esempio, un certificato in una X509Credential può attestare diversi nomi di dominio o indirizzi e-mail nell'estensione subjectAltName. Un'applicazione può decidere di presentarli tutti all'utente, oppure, se conosce un nome di dominio o un indirizzo e-mail “desiderato”, può verificare che l'identificatore desiderato sia tra quelli attestati. Utilizzando la terminologia di [RFC6125], una credenziale fornisce “identificatori presentati” e spetta all'applicazione fornire un “identificatore di riferimento” per il client autenticato, se presente.
```
// See the "MLS Credential Types" IANA registry for values
uint16 CredentialType;

struct {
    opaque cert_data<V>;
} Certificate;

struct {
    CredentialType credential_type;
    select (Credential.credential_type) {
        case basic:
            opaque identity<V>;

        case x509:
            Certificate certificates<V>;
    };
} Credential;
```
#### Credential Validation
L'applicazione che utilizza MLS è responsabile di specificare quali identificatori ritiene accettabili per ciascun membro di un gruppo (dominio, email etc...).
L'autenticazione di un membro consiste nel verificare che le credenziali a sua disposizione siano in un formato supportato e successivamente verificando che le credenziali siano corrette. La parte di sistema che si occupa di queste funzionalità è chiamata **Authentication Service(AS)**. Si dice che la credenziale di un membro è stata convalidata con l'AS quando quest'ultimo verifica che gli identificatori presentati della credenziale sono correttamente associati al campo signature_key del LeafNode del membro e che tali identificatori corrispondono agli identificatori di riferimento del membro. Ogni volta che una nuova credenziale viene introdotta nel gruppo, DEVE essere convalidata con il AS. Nei casi in cui la credenziale di un membro viene sostituita, come nei casi di Update e Commit l'AS DEVE anche verificare che l'insieme degli identificatori presentati nella nuova credenziale sia valido come successore dell'insieme degli identificatori presentati nella vecchia credenziale, secondo la politica dell'applicazione.
#### Credential Expiry and Revocation
In alcuni credentials schemes delle credenziali valide possono scadere o diventare "invalide", questo è il caso dei certificati x.509. In generale, per evitare problemi operativi come il rifiuto da parte dei nuovi membri di credenziali scadute in un gruppo, le applicazioni che utilizzano tali credenziali devono garantire, per quanto possibile, che tutte le credenziali in uso in un gruppo siano sempre valide. Se un membro scopre che la sua credenziale è scaduta (o lo sarà presto), deve emettere un Update o un Commit che la sostituisca con una credenziale valida. Per questo motivo, i membri DOVREBBERO accettare proposte di aggiornamento e impegni emessi da membri con credenziali scadute, se la credenziale nell'aggiornamento o nell'impegno è valida. Analogamente, quando un client elabora messaggi inviati nel passato (ad esempio, sincronizzandosi con un gruppo dopo essere stato offline), il client DOVREBBE accettare firme da membri con credenziali scadute, poiché la credenziale potrebbe essere stata valida al momento dell'invio del messaggio (ricordarsi che la chat è asincrona).
**Revocation**: Alcuni schemi di credenziali consentono anche la revoca delle credenziali. La revoca è simile alla scadenza, in quanto una credenziale precedentemente valida diventa non valida. Di conseguenza, la maggior parte delle considerazioni fatte sopra si applicano anche alle credenziali revocate. Tuttavia, le applicazioni potrebbero voler trattare le credenziali revocate in modo diverso, ad esempio eliminando i membri con credenziali revocate e lasciando ai membri con credenziali scadute il tempo di aggiornare le credenziali.

### Message Framing
#TODO

## The MLS Approach: TreeSync, TreeKEM, TreeDEM
Il protocollo MLS raggiunge i suoi obiettivi di performance e sicurezza utilizzando alberi binari per rappresentare la struttura dei dati di gruppo e per stabilire in modo efficiente le chiavi di gruppo. In particolare, l'array di membri raffigurato sopra si trasforma in foglie di un albero binario, dove i nodi interni rappresentano sottogruppi costituiti dai membri sottostanti.
![[mls-array-tree.png]]
<sup>Fig. 1</sup>
Ad alto livello, MLS può essere suddiviso in tre sottoprotocolli che popolano, sincronizzano e utilizzano questa struttura di dati ad albero per stabilire chiavi condivise per il gruppo e utilizzarle per la messaggistica sicura. Chiamiamo questi tre sottoprotocolli TreeSync, TreeKEM e TreeDEM. Questa decomposizione di MLS non è esplicitamente specificata nello standard.
- **TreeSync**: Gestione autenticata del gruppo Il sottoprotocollo TreeSync garantisce che tutti i membri del gruppo abbiano una visione coerente e autenticata dello stato del gruppo, compresi l'array dei membri e le chiavi memorizzate nella struttura dati ad albero MLS. TreeSync definisce tutte le operazioni di gestione del gruppo e utilizza tecniche multiple di hashing dell'albero (non dissimili dagli alberi di Merkle) e firme per garantire l'accordo di appartenenza e l'integrità dello stato del gruppo. Questo serve come precondizione essenziale per la creazione delle chiavi.
- **TreeKEM**: Il sottoprotocollo TreeKEM utilizza la struttura dei dati ad albero per generare chiavi di sottogruppo per ogni nodo interno dell'albero, compresa una chiave di gruppo per la radice che viene condivisa tra tutti i membri del gruppo nell'epoca corrente. Ogni volta che i membri del gruppo cambiano, TreeKEM genera una nuova chiave di gruppo e la trasmette in modo efficiente a tutti gli altri membri. Finché tutti i membri contribuiscono attivamente al gruppo, tutte le operazioni di TreeKEM hanno un costo proporzionale all'altezza dell'albero, cioè logaritmico rispetto alla dimensione del gruppo. Tuttavia, se solo alcuni membri contribuiscono attivamente, il costo di ogni operazione può diventare lineare rispetto alle dimensioni del gruppo.
- **TreeDEM**: Il sottoprotocollo TreeDEM utilizza le chiavi di gruppo stabilite da TreeKEM per crittografare e autenticare i messaggi applicativi inviati in ogni epoca. TreeDEM garantisce la  forward security dei messaggi applicativi, utilizzando la struttura dei dati ad albero per decidere quali chiavi derivare e quando cancellarle.
### TreeKEM
TreeKEM è un sottoprotocollo di MLS che si basa su collision-resistant hash function (**H**), un meccanismo di cifratura a chiave pubblica (pgen, penc, pdec), una funzione pseudo-random utilizzata per la key derivation function (**kdf**) e uno schema di cifratura autenticato(gen, enc, dec). 
**trees of sub-groups**: Assumiamo che ogni gruppo di messaggistica nello stato globale sia la radice di un albero in cui ogni nodo dell'albero corrisponde a un sottogruppo. Le foglie dell'albero sono dispositivi (cioè gruppi con un solo membro). Per semplicità, supponiamo un albero binario bilanciato a sinistra, ma il protocollo è facilmente generalizzabile a un albero di arietà e struttura arbitraria. Quindi, ogni gruppo di messaggistica composto da n dispositivi forma un albero di altezza log⁡(n), dove ogni dispositivo (nodo foglia) è membro di fino a log⁡(n) gruppi (i suoi antenati nell'albero) e la radice corrisponde al gruppo di messaggistica.
**Local State**: 
- **M_i**: sono i gruppi di messaggistica a cui d_i appartiene
- **encryption_key**: M_i --> K_ae : chiavi crittografiche autenticate per i gruppi di messaggistica di d_i
- **G_i**: insieme di sottogruppi a cui d_i appartiene compreso il sottogruppo {d_i}
- **secret_key**: G_i --> K_s: chiavi segrete per i gruppi di messaggistica a cui d_i appartiene
- **public_key**: sibling(G_i) --> P: chiavi pubbliche per i gruppi fratelli di G_i
Quindi, per ogni gruppo di messaggistica g_i , d_i deve conservare la chiave crittografica del gruppo, le chiavi segrete per tutti i gruppi sul path(d_i, g_j) e le chiavi pubbliche per tutti i gruppi sul copath(d_i, g_j).
- **path(d_i,g_j)** --> g_0,....,g_j: intendiamo la sequenza di gruppi da d_i(nodo foglia, dispositivo) alla radice dell'albero g_j, dove g_0 = {d_i}, g_(k+1) = parent(g_k)
- **copath(d_i,g_j)** --> g_0^',...,g_j^': i fratelli di ogni gruppo nel path(d_i,g_j)
Quindi, i requisiti di archiviazione per ogni gruppo di dimensione n a cui di decide di aderire sono O(log(n)).
#### Differenza con ART
Vale la pena notare che fino a questo punto le strutture di gruppo e gli stati locali memorizzati in ART e TreeKEM sono gli stessi. L'unica differenza è che in ART le chiavi di ogni gruppo (chiave segreta(g), chiave pubblica(g)) devono corrispondere a una coppia di chiavi Diffie-Hellman, mentre in TreeKEM possiamo scegliere qualsiasi coppia di chiavi che supporti l'incapsulamento delle chiavi (KEM).
#### Computing Tree Keys
Per calcolare le chiavi di gruppo, è necessario assegnare a ogni nodo dell'albero una coppia di chiavi nota solo ai membri del gruppo, cioè ai dispositivi che appaiono come foglie nel sottoalbero corrente. In una foglia, generiamo coppie di chiavi KEM fresche per ogni dispositivo (chiave segreta(d_i), chiave pubblica(d_i)). Per ogni nodo interno, la chiave segreta viene calcolata come hash della chiave segreta di uno dei due figli, intuitivamente l'ultimo figlio che ha effettuato un'operazione di gruppo. La chiave di autenticazione per la cifratura del gruppo di messaggistica (encryption key(d_j)) è derivata (come una catena di invocazioni KDF) dalla sequenza di chiavi alla radice dell'albero. In TreeKEM, quindi, le chiavi interne dei nodi dipendono solo da uno dei due figli. Le chiavi dei nodi interni di TreeKEM non sono contributive (a differenza di ART) e questo porta direttamente ad alcuni dei vantaggi di TreeKEM per quanto riguarda la concorrenza. Si noti che la chiave di cifratura del gruppo di messaggistica è ancora contributiva, nel senso che incorpora il materiale di cifratura di tutti i nodi che hanno avviato un'operazione di gruppo.
![[TreeKEM.png|Caption]]
<sup>Fig. 2</sup>
L'immagine Fig.2 rappresenta un gruppo appena creato di cinque dispositivi (A,B,C,D,E). Ogni nodo è annotato con la chiave segreta di gruppo assegnata a quel nodo (per semplicità, le nostre figure utilizzano il nome del dispositivo per riferirsi anche alla sua chiave segreta). Le chiavi dell'albero sono calcolate come se i nodi fossero stati aggiunti in ordine da sinistra a destra, in modo che l'ultimo dispositivo (E) determini la chiave dei suoi antenati.
![[updateKEM.png]]
<sup>Fig. 3: Il dispositivo B aggiorna le chiavi per tutti i gruppi a cui appartiene, ottenendo una nuova chiave di gruppo K1</sup>
La Fig.3 rappresenta l'albero dopo che il dispositivo B ha effettuato un aggiornamento, generando una nuova chiave B' e installando una sequenza di chiavi con hash lungo l'albero.

![[addKEM.png]]
<sup>Fig 4: Il dispositivo F viene aggiunto al gruppo e si ottiene una nuova chiave di gruppo K2.</sup>
La Fig.4 mostra l'albero dopo l'aggiunta di un nuovo dispositivo F al gruppo con una nuova chiave F e l'installazione di una sequenza di chiavi hash lungo l'albero.

![[removeKEM.png]]
<sup>Fig 5: Il dispositivo C viene rimosso dal gruppo e si ottiene una nuova chiave di gruppo K3.</sup>

La fig. 5 mostra l'albero dopo che il dispositivo C è stato rimosso dal gruppo e a tutti i suoi gruppi è stata data una sequenza di chiavi hash a partire da una nuova chiave C' che **è sconosciuta a C**.

##### Concurrent operations
In TreeKEM, se due operazioni vengono eseguite simultaneamente, ci sono molti modi per unirle. Ad esempio, si può assumere che le operazioni provenienti dai dispositivi di un sottoalbero di sinistra debbano essere eseguite prima dei dispositivi di destra. Oppure si possono applicare politiche più sottili come: gli aggiornamenti devono essere elaborati prima delle rimozioni. Possiamo anche affidarci al servizio di consegna per ordinare totalmente tutte le operazioni in modo che tutti i dispositivi le elaborino nello stesso ordine. La **proprietà chiave** di TreeKEM è che la maggior parte delle operazioni sono “unificabili”, nel senso che qualsiasi dispositivo che riceva due operazioni concorrenti sarà in grado di elaborarle ed eseguirle entrambe senza doverne rifiutare una o chiedere ulteriori informazioni. 

![[issueUpdateKEM.png]]
<sup>Fig. 6</sup>
La Figura 6 mostra come due aggiornamenti concomitanti possano essere uniti utilizzando l'ordine dei dispositivi come elemento di parità. Poiché entrambi gli aggiornamenti sono stati emessi rispetto al vecchio stato globale, tuttavia, il nuovo albero non è ancora completamente aggiornato, nel senso che un aggressore che conosce le vecchie chiavi di A e D è in grado di calcolare la nuova chiave di gruppo. In TreeKEM, se due operazioni vengono eseguite simultaneamente, ci sono molti modi per unirle. Ad esempio, si può assumere che le operazioni provenienti dai dispositivi di un sottoalbero di sinistra debbano essere eseguite prima dei dispositivi di destra. Oppure si possono applicare politiche più sottili come: gli aggiornamenti devono essere elaborati prima delle rimozioni. Possiamo anche affidarci al servizio di consegna per ordinare totalmente tutte le operazioni in modo che tutti i dispositivi le elaborino nello stesso ordine. La proprietà chiave di TreeKEM è che la maggior parte delle operazioni sono “unificabili”, nel senso che qualsiasi dispositivo che riceva due operazioni concorrenti sarà in grado di elaborarle ed eseguirle entrambe senza doverne rifiutare una o chiedere ulteriori informazioni. Poiché entrambi gli aggiornamenti sono stati emessi rispetto al vecchio stato globale, tuttavia, il nuovo albero non è ancora completamente aggiornato, nel senso che un aggressore che conosce le vecchie chiavi di A e D è in grado di calcolare la nuova chiave di gruppo, questo poiché H2(D′) e H2(A′) sono state inviate cifrate alle vecchie chiavi pubbliche di A e D. TreeKEM consente l'esecuzione immediata degli aggiornamenti concorrenti, ma i vantaggi della sicurezza post-compromissione non si applicano fino a quando non viene emesso un altro aggiornamento sullo stato unito. Poiché l'elaborazione di un aggiornamento comporta la sovrascrittura delle chiavi, affinché gli aggiornamenti concorrenti funzionino correttamente, le implementazioni devono conservare un insieme di chiavi storiche in modo da poter elaborare gli aggiornamenti inviati sulla base dello stesso stato iniziale Sk. Questo è compatibile con diversi algoritmi di conservazione dello stato, a patto che le implementazioni concordino su quali aggiornamenti debbano essere elaborati e quali rifiutati (e quindi quando le chiavi possono essere scartate).
![[updateAfterIssueKEM.png]]
<sup>Fig. 7</sup>
Dopo aver elaborato gli aggiornamenti contemporanei dei dispositivi A e D, il dispositivo B invia un nuovo aggiornamento. Questo aggiornamento si propaga lungo l'albero, “curando” così tutti i nodi dell'albero in uno stato unito coerente. Una volta elaborato il nuovo aggiornamento, si ottiene una PCS contro la compromissione di tutti i dispositivi; in altre parole, un avversario che compromette i vecchi stati di A, B e D non può più calcolare la nuova chiave di gruppo.

#### Parent Node Content

```
struct {
    HPKEPublicKey encryption_key;
    opaque parent_hash<V>;
    uint32 unmerged_leaves<V>;
} ParentNode;
```

Il campo encryption_key contiene una chiave pubblica HPKE la cui chiave privata è detenuta solo dai membri alle foglie tra i suoi discendenti. Il campo parent_hash contiene un hash del nodo genitore di questo nodo, come descritto nella Sezione 7.9. Il campo unmerged_leaves elenca le foglie sotto questo nodo genitore che sono unmerged, secondo i loro indici tra tutte le foglie dell'albero. Le voci del vettore unmerged_leaves DEVONO essere ordinate in ordine crescente.

#### Leaf Node Content
Un nodo foglia dell'albero descrive tutti i dettagli del singolo client e firmati da esso.

```
struct {
    HPKEPublicKey encryption_key;
    SignaturePublicKey signature_key;
    Credential credential;
    Capabilities capabilities;

    LeafNodeSource leaf_node_source;
    select (LeafNode.leaf_node_source) {
        case key_package:
            Lifetime lifetime;

        case update:
            struct{};

        case commit:
            opaque parent_hash<V>;
    };

    Extension extensions<V>;
    /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
    opaque signature<V>;
} LeafNode;
```
