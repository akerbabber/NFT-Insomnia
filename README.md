# MultiUtilityNFT

MultiUtilityNFT is a smart contract that implements a multi-phase NFT minting process. It features whitelisting using Merkle Trees, discounted minting with EIP712 signatures, and a vesting mechanism integrated with Sablier.

---

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Notes](#notes)

---

## Installation

### 1. Install Foundry

Install Foundry by running:

```bash
curl -L https://foundry.paradigm.xyz | bash
```

### 2. Clone the Repository

Clone the repository and navigate into the project directory:

```bash
git clone <repo-url>
cd <repo-name>
```

### 3. Install Dependencies

Install the project dependencies using Forge:

```bash
forge install
```

---

## Usage

### Running Tests

Execute the complete test suite with:

```bash
forge test
```

### Generating Code Coverage

Generate a code coverage report by running:

```bash
forge coverage
```

---

## Notes

Thank you for the opportunity to work on this task. Here are some important design considerations and decisions made during development:

- **Test Coverage:**  
  - Test cases follow the Branching tree technique (BTT)  to cover all requirements.
  - Achieved 100% test coverage for the contracts.

- **Documentation:**  
  - The NFT contract is well-documented using NatSpec comments for better clarity.

- **OpenZeppelin Contracts:**  
  - Instead of using the main branch, tagged releases of OpenZeppelin contracts are utilized for improved stability.
  - The project employs the latest version (5.2.0) to ensure the best security updates and improvements.

- **Solidity Version:**  
  - Solidity 0.8.26 is chosen for its robustness and battle-tested nature compared to newer releases.

- **Security Checks:**  
  - Tools like **wake** and **slither** are used for thorough security analysis.

- **Gas Optimization:**  
  - The contract adopts the checks-effects-interactions pattern, omitting the Reentrancy Guard to avoid unnecessary gas costs.

- **Signature and Replay Protection:**  
  - Implements nonces and EIP712 for secure signature validation and replay protection.
  - Uses separate `v, r, s` signatures (instead of compact signatures) to mitigate signature malleability issues, as noted in previous vulnerabilities ([OpenZeppelin advisory](https://github.com/advisories/GHSA-4h98-2769-gh6h)).

- **Merkle Tree Security:**  
  - Employs a double-hashing method for Merkle leaves to prevent second preimage attacks and to maintain compatibility with OpenZeppelin’s Merkle Tree implementation—even though the data (addresses) is only 20 bytes long.

- **Safe Token Transfers:**  
  - Utilizes OpenZeppelin’s SafeERC20 to securely handle token transfers, accounting for tokens that may not revert on failure.

- **Vesting Integration:**  
  - Vesting functionality is validated by forking the mainnet and simulating vesting scenarios using mainnet addresses and contracts.

---
