- [x] Milestone 1
  - [x] Implement AES encryption to Lownet
    - [x] Encryption key can be set manually via the serial interface
- [ ] Milestone 2
  - [ ] Implement the digital signature verification using the provided sample message
  - [ ] Implement support for the multi-frame signed packets
  - [ ] Implement the new command protocol that obsoletes the insecure time protocol

I understand it as such that only the command frames should include the signatures.

Note: Include time-stamps and other relevant information to the message before signing it!

- [ ] Signature verification
