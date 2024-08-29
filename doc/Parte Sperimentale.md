## Prerequisiti
Molte operazioni in OpenMLS richiedono un Provider, un oggetto che mette a disposizione tutti i requisiti crittografici e lo si può creare nel seguente modo
```
    use openmls_rust_crypto::OpenMlsRustCrypto;

    let provider = OpenMlsRustCrypto::default();
```
## Credenziali 
OpenMLS consente ai clienti di creare credenziali. Una BasicCredential, attualmente l'unico tipo di credenziale supportato da OpenMLS, consiste solo nell'identità. Pertanto, per creare una nuova Credenziale, sono necessari i seguenti input:
```rust
    let credential = Credential::new(identity, credential_type).unwrap();
```
- **identity**: Una stringa che unifica univocamente il client
- **credential_type**: tipologia di credenziali
Dopo aver creato il bundle di credenziali, i clienti devono creare le chiavi per esso. OpenMLS fornisce una semplice implementazione di BasicCredential per i test e per dimostrare come utilizzare le credenziali
```rust
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.key_store()).unwrap();
```
