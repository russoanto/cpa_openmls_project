use openmls::prelude::{*, config::CryptoConfig};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls_basic_credential::SignatureKeyPair;
use openmls::treesync;
use openmls_test::openmls_test;
use openmls_traits::signatures::Signer;

// Now let's create two participants.

// A helper to create and store credentials.
fn generate_credential_with_key(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(identity, credential_type).unwrap();
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    signature_keys
        .store(backend.key_store())
        .expect("Error storing signature keys in key store.");
     
    (
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

// A helper to create key package bundles.
fn generate_key_package(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackage {
    // Create the key package
    KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            signer,
            credential_with_key,
        )
        .unwrap()
}

fn main() {
    // Define ciphersuite ...
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // ... and the crypto backend to use.
    let backend = &OpenMlsRustCrypto::default();

    // First they need credentials to identify them
    let (sasha_credential_with_key, sasha_signer) = generate_credential_with_key(
        "Sasha".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );
    let (maxim_credential_with_key, maxim_signer) = generate_credential_with_key(
        "Maxim".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );
    println!("Credential Generated!!!");

    // Generate KeyPackages
    let maxim_key_package = generate_key_package(ciphersuite, backend, &maxim_signer, maxim_credential_with_key);

    // Now Sasha starts a new group ...
    let mut sasha_group = MlsGroup::new(
        backend,
        &sasha_signer,
        &MlsGroupConfig::default(),
        sasha_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    // ... and invites Maxim.
    // The key package has to be retrieved from Maxim in some way. Most likely
    // via a server storing key packages for users.
    let (mls_message_out, welcome_out, group_info) = sasha_group
        .add_members(backend, &sasha_signer, &[maxim_key_package])
        .expect("Could not add members.");

    // Sasha merges the pending commit that adds Maxim.
    sasha_group
    .merge_pending_commit(backend)
    .expect("error merging pending commit");

    // Sascha serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
    .tls_serialize_detached()
    .expect("Error serializing welcome");

    // Maxim can now de-serialize the message as an [`MlsMessageIn`] ...
    let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
    .expect("An unexpected error occurred.");

    // ... and inspect the message.
    let welcome = match mls_message_in.extract() {
    MlsMessageInBody::Welcome(welcome) => welcome,
    // We know it's a welcome message, so we ignore all other cases.
    _ => unreachable!("Unexpected message type."),
    };

    // Now Maxim can join the group.
    let mut maxim_group = MlsGroup::new_from_welcome(
        backend,
        &MlsGroupConfig::default(),
        welcome,
        // The public tree is need and transferred out of band.
        // It is also possible to use the [`RatchetTreeExtension`]
        Some(sasha_group.export_ratchet_tree().into()),
    )
    .expect("Error joining group from Welcome");

    assert_eq!(sasha_group.members().count(), 2);

// You can now send `encrypted_message` to the other group members.


    let message_maxim = b"Hi, I'm Maxim!";
    let mls_message_out = sasha_group
        .create_message(backend, &maxim_signer, message_maxim)
        .expect("Error creating application message.");

    

    let (mls_message_out, welcome_option, _group_info) = sasha_group
        .commit_to_pending_proposals(backend, &maxim_signer)
        .expect("Could not commit to pending proposals.");


    // === Maxim sends a message to Sasha ===
    let message_maxim = b"Hi, I'm Maxim!";
    let queued_message = maxim_group
        .create_message(backend, &maxim_signer, message_maxim)
        .expect("Error creating application message");

    let processed_message = sasha_group
    .process_message(
        backend,
        queued_message
            .clone()
            .into_protocol_message()
            .expect("Unexpected message type"),
    )
    .expect("Could not process message.");

    let sender = processed_message.credential().clone();

    // Check that we received the correct message
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        assert_eq!(application_message.into_bytes(), message_maxim);
        println!("Messaggio ricevuto correttamente!!!!!");

        // Check that Alice sent the message
        assert_eq!(
            &sender,
            maxim_group
                .credential()
                .expect("An unexpected error occurred.")
        );
    } else {
        unreachable!("Expected an ApplicationMessage.");
    }
}
