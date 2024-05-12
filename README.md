## Cross-Chain Vulnerability PoC using Pigeon
This repository demonstrates how to use the Pigeon library to perform a Proof of Concept (PoC) of a cross-chain vulnerability in a vulnerable smart contract. The PoC exploits a lack of sender validation in the vulnerable contract, allowing an attacker to manipulate the contract's state maliciously.

The `VulnerableContract` is a simple contract that receives cross-chain messages through the Hyperlane protocol. However, it has a vulnerability where it does not validate the sender of the message, allowing anyone to update the value state variable.
The CrossChainBugPoc contract is a test contract that uses the Pigeon library to simulate cross-chain interactions and demonstrate the vulnerability. It performs the following steps:

For more information on using the Pigeon library, refer to the [Pigeon](https://github.com/exp-table/pigeon) documentation.