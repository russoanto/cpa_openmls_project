## Prerequisiti
Molte operazioni in OpenMLS richiedono un Provider, un oggetto che mette a disposizione tutti i requisiti crittografici e lo si può creare nel seguente modo
```rust
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

## KeyPackage
Per consentire la creazione asincrona di gruppi attraverso la pre-pubblicazione di materiale chiave, nonché per rappresentare i client nel gruppo, MLS si basa su pacchetti di chiavi. I pacchetti di chiavi contengono diverse informazioni:
- una chiavi HPKE per abilitare la funzione di distribuzione della chiave di gruppo di base di MLS
- tempo di vita entro cui un KeyPackage è valido
- Informazioni sulle capabilities del client (es. versione di MLS supportata)
- estensioni che il client vuole includere
- una delle credenziali del cliente, nonché una firma sull'intero pacchetto di chiavi utilizzando la chiave privata corrispondente alla chiave pubblica di firma della credenziale

Prima che la comunicazione tra client possa avvenire abbiamo bisogno di creare questo KeyPackage, il client manterrà immagazzinato le chiavi private in un keystore.

```rust
    // Create the key package
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            CryptoConfig::with_default_version(ciphersuite),
            provider,
            signer,
            credential_with_key,
        )
        .unwrap()
```
Il client deve scegliere:
- `ciphersuites`: deve scegliere tra una lista di ciphersuite supportati dal client
- `extensions`: una serie di estensioni supportate
## Group Configuration
MlsGroupJoinConfig contiene le seguenti opzioni di configurazione rilevanti per il tempo di esecuzione di un gruppo Mls e può essere impostato per ogni cliente quando si unisce un gruppo.
```rust
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .external_senders(vec![ExternalSender::new(
            ds_credential_with_key.signature_key.clone(),
            ds_credential_with_key.credential.clone(),
        )])
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .use_ratchet_tree_extension(true)
        .build();
```