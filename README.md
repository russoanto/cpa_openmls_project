# Simple MLS Protocol Demonstration

This project is developed as part of the Applied Cryptography course and aims to demonstrate the basic functioning of the Messaging Layer Security (MLS) protocol. The application simulates a secure group messaging environment where users can join, leave, and communicate securely using the MLS protocol.
Features:
This test simulates various group operations like Add, Update, Remove in a small group
- Alice creates a group
- Alice adds Bob
- Alice sends a message to Bob
- Bob updates and commits
- Alice updates and commits
- Bob adds Charlie
- Charlie sends a message to the group
- Charlie updates and commits
- Charlie removes Bob

# Purpose

The primary purpose of this project is educational, providing a hands-on understanding of how the MLS protocol works in practice. This includes key management, group membership dynamics, and message encryption, which are crucial for building secure communication systems.
Usage

    - Start the application and create a new group.
    - Invite other users to join the group.
    - Send encrypted messages within the group.

# How to launch
In the cpa_openmls_project folder run:
```bash
	cargo run
```
