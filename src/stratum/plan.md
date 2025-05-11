A Stratum server should meet the following requirements.

- [ ] Provides a TCP socket that listens to incoming connections on a port provided.
- [ ] For each incoming connection we follow the stratum messages protocol.
- [ ] Get block templates from bitcoin node.
- [ ] For a given block template we generate work that needs to be worked on by ASICs machines.
- [ ] We store the block template as a serialized compact block in the database.
- [ ] We generate a coinbase for a single coinbase address in v1.
- [ ] Move on to use coinbase for multiple users. We need this for Hydrapool and P2Pool.
