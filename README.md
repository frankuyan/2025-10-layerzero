# LayerZero audit details
- Total Prize Pool: $100,000 in USDC 
    - HM awards: up to $92,640 in USDC 
        - If no valid Highs or Mediums are found, the HM pool is $0 
    - QA awards: $3,860 in USDC
    - Judge awards: $3,000 in USDC
    - Scout awards: $500 USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts October 24, 2025 20:00 UTC
- Ends November 7, 2025 20:00 UTC

### ❗ Important notes for wardens
1. Judging phase risk adjustments (upgrades/downgrades):
    - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
    - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
    - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

The Alexandria lib and the starknet core lib (currently in audit) should be two exceptions which will need to be ruled out for the competition. The contacts in scope for this competition references these 2 libraries but they need to be excluded.
malformed byte array issue is already discovered and will not count as a bug finding
where two different Byte Arrays result in the same keccak hash if one of them is malformed

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

# Overview

[ ⭐️ SPONSORS: add info here ]

## Links

- **Previous audits:**  N/A
  - ✅ SCOUTS: If there are multiple report links, please format them in a list.
- **Documentation:** https://github.com/LayerZero-Labs/EPv2-Starknet/blob/main/layerzero/README.md
- **Website:** [LayerZero.network](https://layerzero.network/)
- **X/Twitter:** [@layerzero_core](https://x.com/layerzero_core)

---

# Scope

[ ✅ SCOUTS: add scoping and technical details here ]

### Files in scope
- ✅ This should be completed using the `metrics.md` file
- ✅ Last row of the table should be Total: SLOC
- ✅ SCOUTS: Have the sponsor review and and confirm in text the details in the section titled "Scoping Q amp; A"

*For sponsors that don't use the scoping tool: list all files in scope in the table below (along with hyperlinks) -- and feel free to add notes to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [contracts/folder/sample.sol](https://github.com/code-423n4/repo-name/blob/contracts/folder/sample.sol) | 123 | This contract does XYZ | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |

### Files out of scope
✅ SCOUTS: List files/directories out of scope

# Additional context

## Areas of concern (where to focus for bugs)
- Security issues on DVN / ULN interactionThe Alexandria lib and the starknet core lib (currently in audit) should be two exceptions which will need to be ruled out for the competition. The contacts in scope for this competition references these 2 libraries but they need to be excluded.
malformed byte array issue is already discovered and will not count as a bug finding
- Starknet specific problems on handling Storage, is there a way to grief the Endpoint or ULN which will be immutable?
- Censorship resistance, is there a way on the native payment path LayerZero can use its permissions to censor user messages? this should not be possible with proper configuration
- Starknet specific behaviour

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

## Main invariants

Endpoint owner should not be able to censor messages
Endpoint is immutable
Only delegate or OApp can set configs for OApp
ULN is immutable
ULN owner should not be able to censor messages through native path
DVN is secured through its multisig
DVN cannot suffer replay attack
Only Admin can execute arbitrary signed payload through DVN
DVN can {ermissionless grant Admin through signed payload



✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

## All trusted roles in the protocol

Endpoint

Owner — Controlled by LayerZero

Sets LayerZero token address

Registers libraries

Defines default send/receive libraries and their timeouts

Delegate — Controlled by OApp Owner

Manages OApp configurations (send/receive configs, libraries, timeouts)

Clears and processes messages on the endpoint

Can skip, nullify, or burn messages

DVN (Decentralized Verification Network)

Admin — Controlled by DVN multisig / Admin

Grants roles

Executes operations

Sets destination config, price feed, supported options, and fees

Signer — Controlled by DVN multisig

Signs calldata to be executed on the DVN

A group of signers can collectively change the admin (permissionless)

Message Lib — Controlled by DVN multisig

Can assign jobs

UltraLightNode

Owner — Sets configs for UltraLightNode

Defines send/receive and executor configs

Sets treasury native fee cap

Endpoint — Endpoint for ULN

Can call send

Treasury

Owner — Controlled by LayerZero

Sets fee basis points

Withdraws tokens

Sets LayerZero token fee library

✅ SCOUTS: Please format the response above 👆 using the template below👇

| Role                                | Description                       |
| --------------------------------------- | ---------------------------- |
| Owner                          | Has superpowers                |
| Administrator                             | Can change fees                       |

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

## Running tests

Install asdf package manager
asdf install
cd layerzero
scarb fetch
scarb build
scarb test

✅ SCOUTS: Please format the response above 👆 using the template below👇

```bash
git clone https://github.com/code-423n4/2023-08-arbitrum
git submodule update --init --recursive
cd governance
foundryup
make install
make build
make sc-election-test
```
To run code coverage
```bash
make coverage
```

✅ SCOUTS: Add a screenshot of your terminal showing the test coverage

## Miscellaneous
Employees of LayerZero and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.
