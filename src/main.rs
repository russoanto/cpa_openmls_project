use openmls::{
    prelude::{test_utils::new_credential, *},
    storage::OpenMlsProvider,
    treesync::LeafNodeParameters,
};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls_traits::signatures::Signer;

fn generate_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &Provider,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
        .key_package()
        .clone()
}

/// Simulates various group operations like Add, Update, Remove in a
/// small group
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice sends a message to Bob
///  - Bob updates and commits
///  - Alice updates and commits
///  - Bob adds Charlie
///  - Charlie sends a message to the group
///  - Charlie updates and commits
///  - Charlie removes Bob
fn main() {
    // Define ciphersuite ...
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_id = GroupId::from_slice(b"Test Group");

    //Define the backend for the partecipants
    let alice_provider = &OpenMlsRustCrypto::default();
    let bob_provider = &OpenMlsRustCrypto::default();
    let charlie_provider = &OpenMlsRustCrypto::default();

    // Generate credentials with keys
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let (charlie_credential, charlie_signer) = 
        new_credential( charlie_provider, b"Charlie", ciphersuite.signature_algorithm(),);

    // Generate KeyPackages for Bob
    let bob_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        bob_provider,
        bob_credential.clone(),
        &bob_signer,
    );

    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id.clone(),
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Alice adds Bob ===
    let welcome =
        match alice_group.add_members(alice_provider, &alice_signer, &[bob_key_package]) {
            Ok((_, welcome, _)) => welcome,
            Err(e) => panic!("Could not add member to group: {e:?}"),
        };

    // Check that we received the correct proposals
    if let Some(staged_commit) = alice_group.pending_commit() {
        let add = staged_commit
            .add_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was added
        assert_eq!(
            add.add_proposal().key_package().leaf_node().credential(),
            &bob_credential.credential
        );
        // Check that Alice added Bob
        assert!(
            matches!(add.sender(), Sender::Member(member) if *member == alice_group.own_leaf_index())
        );
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    alice_group
        .merge_pending_commit(alice_provider)
        .expect("error merging pending commit");

    // Check that the group now has two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Bob are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating StagedWelcome from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from StagedWelcome");

    // Make sure that both groups have the same members
    assert!(alice_group.members().eq(bob_group.members()));

    // Make sure that both groups have the same epoch authenticator
    assert_eq!(
        alice_group.epoch_authenticator().as_slice(),
        bob_group.epoch_authenticator().as_slice()
    );

    // === Alice sends a message to Bob ===
    let message_alice = b"Hi, I'm Alice!";
    let queued_message = alice_group
        .create_message(alice_provider, &alice_signer, message_alice)
        .expect("Error creating application message");

    let processed_message = bob_group
        .process_message(
            bob_provider,
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
        assert_eq!(application_message.into_bytes(), message_alice);
        // Check that Alice sent the message
        assert_eq!(
            &sender,
            alice_group
                .credential()
                .expect("An unexpected error occurred.")
        );
    } else {
        unreachable!("Expected an ApplicationMessage.");
    }

    // === Bob updates and commits ===
    let (queued_message, _welcome_option, _group_info) = bob_group
        .self_update(bob_provider, &bob_signer, LeafNodeParameters::default())
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // Check that we received the correct message
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        // Merge staged Commit
        alice_group
            .merge_staged_commit(alice_provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }
    // Make sure that both groups have the same epoch authenticator
    // assert_eq!(
    //     alice_group.epoch_authenticator().as_slice(),
    //     bob_group.epoch_authenticator().as_slice()
    // );

    bob_group
        .merge_pending_commit(bob_provider)
        .expect("error merging pending commit");

    // Check that both groups have the same state
    assert_eq!(
        alice_group
            .export_secret(alice_provider, "", &[], 32)
            .unwrap(),
        bob_group.export_secret(bob_provider, "", &[], 32).unwrap()
    );

    // Make sure that both groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    // === Bob adds Charlie ===
    let charlie_key_package = generate_key_package(
        ciphersuite,
        Extensions::empty(),
        charlie_provider,
        charlie_credential,
        &charlie_signer,
    );

    let (queued_message, welcome, _group_info) = bob_group
        .add_members(bob_provider, &bob_signer, &[charlie_key_package])
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    bob_group
        .merge_pending_commit(bob_provider)
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(alice_provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("expected the message to be a welcome message");

    let mut charlie_group = StagedWelcome::new_from_welcome(
        charlie_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(charlie_provider)
    .expect("Error creating group from staged join");

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree(),
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Check that Alice, Bob & Charlie are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    let credential2 = members[2].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Bob");
    assert_eq!(credential2, b"Charlie");

    // === Charlie sends a message to the group ===
    let message_charlie = b"Hi, I'm Charlie!";
    let queued_message = charlie_group
        .create_message(charlie_provider, &charlie_signer, message_charlie)
        .expect("Error creating application message");

    let _alice_processed_message = alice_group
        .process_message(
            alice_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let _bob_processed_message = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");

    // === Charlie updates and commits ===
    let (queued_message, _welcome_option, _group_info) = charlie_group
        .self_update(
            charlie_provider,
            &charlie_signer,
            LeafNodeParameters::default(),
        )
        .unwrap();

    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let bob_processed_message = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    charlie_group
        .merge_pending_commit(charlie_provider)
        .expect("error merging pending commit");

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        alice_group
            .merge_staged_commit(alice_provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Merge Commit
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        bob_group
            .merge_staged_commit(bob_provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that all groups have the same state
    assert_eq!(
        alice_group
            .export_secret(alice_provider, "", &[], 32)
            .unwrap(),
        bob_group.export_secret(bob_provider, "", &[], 32).unwrap()
    );
    assert_eq!(
        alice_group
            .export_secret(alice_provider, "", &[], 32)
            .unwrap(),
        charlie_group
            .export_secret(charlie_provider, "", &[], 32)
            .unwrap()
    );

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree(),
    );
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // === Charlie removes Bob ===
    println!(" >>> Charlie remove bob");
    let (queued_message, _welcome_option, _group_info) = charlie_group
        .remove_members(
            charlie_provider,
            &charlie_signer,
            &[bob_group.own_leaf_index()],
        )
        .expect("Could not remove member from group.");

    // Check that Bob's group is still active
    assert!(bob_group.is_active());

    let alice_processed_message = alice_group
        .process_message(
            alice_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    let bob_processed_message = bob_group
        .process_message(
            bob_provider,
            queued_message
                .clone()
                .into_protocol_message()
                .expect("Unexpected message type"),
        )
        .expect("Could not process message.");
    charlie_group
        .merge_pending_commit(charlie_provider)
        .expect("error merging pending commit");

    // Check that we receive the correct proposal for Alice
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        alice_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(remove.remove_proposal().removed(), members[1].index);
        // Check that Charlie removed Bob
        assert!(
            matches!(remove.sender(), Sender::Member(member) if *member == members[2].index)
        );

        // Merge staged Commit
        alice_group
            .merge_staged_commit(alice_provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that we receive the correct proposal for Alice
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        bob_processed_message.into_content()
    {
        let remove = staged_commit
            .remove_proposals()
            .next()
            .expect("Expected a proposal.");
        // Check that Bob was removed
        assert_eq!(remove.remove_proposal().removed(), members[1].index);
        // Check that Charlie removed Bob
        assert!(
            matches!(remove.sender(), Sender::Member(member) if *member == members[2].index)
        );

        // Merge staged Commit
        bob_group
            .merge_staged_commit(bob_provider, *staged_commit)
            .unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }

    // Check that Bob's group is no longer active
    assert!(!bob_group.is_active());

    // Make sure that all groups have the same public tree
    assert_eq!(
        alice_group.export_ratchet_tree(),
        charlie_group.export_ratchet_tree()
    );

    // Make sure the group only contains two members
    assert_eq!(alice_group.members().count(), 2);

    // Check that Alice & Charlie are the members of the group
    let members = alice_group.members().collect::<Vec<Member>>();
    let credential0 = members[0].credential.serialized_content();
    let credential1 = members[1].credential.serialized_content();
    assert_eq!(credential0, b"Alice");
    assert_eq!(credential1, b"Charlie");

    // Check that Bob can no longer send messages, try with is_ok()
    assert!(bob_group
        .create_message(bob_provider, &bob_signer, b"Should not go through")
        .is_err());
}
