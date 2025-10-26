# LayerZero V2-Starknet Audit Plan & Walkthrough

## AUDIT SCOPE SUMMARY

**In-Scope Files (39 total):**
- **Endpoint** (20 files): Core messaging protocol
- **ULN 302** (10 files): Ultra Light Node message library
- **DVN** (9 files): Decentralized Verifier Network
- **Libraries**: multisig, enumerable_set

**Out of Scope:**
- Alexandria lib (under separate audit)
- Starknet core lib (under separate audit)
- Malformed byte array keccak bug (already known)

---

## PHASE 1: SETUP & UNDERSTANDING (Days 1-2)

### 1.1 Environment Setup
```bash
# Install asdf and dependencies
asdf plugin add scarb
asdf plugin add starknet-foundry
asdf plugin add starknet-devnet
asdf install

# Build and test
cd layerzero
scarb fetch
scarb build
scarb test
```

### 1.2 Architecture Understanding

**Core Components:**
1. **EndpointV2** - Central hub for cross-chain messaging
2. **ULN 302** - Message library for verification
3. **DVN** - Off-chain verification nodes
4. **OApp** - User applications

**Message Flow:**
```
1. SEND: OApp → EndpointV2 (with params)
2. VERIFY: DVNs → Message Lib (validation)
3. COMMIT: Message Lib → Endpoint (payload hash)
4. EXECUTE: EndpointV2 → Receiver
```

### 1.3 Key Documentation Review
- Read layerzero/README.md thoroughly
- Understand the EVM implementation differences
- Map trust boundaries and roles

---

## PHASE 2: THREAT MODELING (Day 3)

### 2.1 Attack Surface Mapping

**Critical Attack Vectors:**

1. **Censorship Attacks**
   - Can Endpoint owner block messages?
   - Can ULN owner block via native path?
   - Check delegation abuse

2. **Storage Griefing**
   - Starknet storage manipulation
   - DoS via storage exhaustion
   - Immutability bypass attempts

3. **DVN/ULN Interaction**
   - Replay attacks on DVN signatures
   - Cross-chain replay
   - Verification bypass

4. **Access Control**
   - Role escalation paths
   - Delegate vs Owner privileges
   - Multisig compromise scenarios

5. **Reentrancy**
   - Starknet-specific reentrancy
   - Cross-function reentrancy
   - Composer callback attacks

---

## PHASE 3: SYSTEMATIC CODE REVIEW (Days 4-8)

### 3.1 Endpoint Analysis [layerzero/src/endpoint/]

**Focus Areas:**

**A. endpoint_v2.cairo**
```
Priority Checks:
□ send() function - Can owner censor?
□ Library registration - Immutability checks
□ Delegate permissions - Proper validation?
□ Nonce management - Overflow/collision
□ Reentrancy guards
```

**B. message_lib_manager/**
```
□ Library registration logic
□ Default library assignment
□ Timeout mechanisms
□ Version conflicts
```

**C. messaging_channel/**
```
□ Channel state management
□ Inbound/outbound nonce tracking
□ Lazy inbound nonce handling
□ State corruption scenarios
```

**D. messaging_composer/**
```
□ Compose message flow
□ Callback security
□ Reentrancy protection
□ Message queuing logic
```

### 3.2 ULN 302 Analysis [layerzero/src/message_lib/uln_302/]

**Focus Areas:**

**A. ultra_light_node_302.cairo**
```
Critical Invariants:
□ verify() - DVN signature validation
□ commitVerification() - Quorum checks
□ Message hash computation
□ Config immutability
□ Owner censorship prevention
```

**B. structs/uln_config.cairo**
```
□ Config storage layout
□ Required/optional DVNs
□ Threshold validation
□ Config update restrictions
```

**C. options.cairo**
```
□ Option parsing logic
□ Gas limit validation
□ Worker options handling
□ Malformed input handling
```

### 3.3 DVN Analysis [layerzero/src/workers/dvn/]

**Focus Areas:**

**A. dvn.cairo**
```
Critical Security:
□ assignJob() - Authorization
□ Signature verification
□ Replay attack prevention
□ Nonce management
□ Cross-chain replay protection
```

**B. Multisig Integration**
```
□ Admin grant mechanism
□ Signer threshold
□ Signature verification
□ Role management
□ Emergency procedures
```

**C. fee_lib/dvn_fee_lib.cairo**
```
□ Fee calculation logic
□ Price feed manipulation
□ Fee bypass scenarios
□ Native token handling
```

### 3.4 Library Analysis

**A. libs/multisig/**
```
□ Signature verification algorithm
□ Quorum logic
□ Signer management
□ Hash collision resistance
□ EIP-712 compliance (if applicable)
```

**B. libs/enumerable_set/**
```
□ Add/remove operations
□ Iteration safety
□ Index bounds checking
□ Storage efficiency
```

---

## PHASE 4: INVARIANT TESTING (Days 9-10)

### 4.1 Main Invariants to Test

```cairo
// Test each invariant programmatically

INVARIANT 1: Endpoint owner CANNOT censor messages
- Try blocking message with owner role
- Verify message still processes

INVARIANT 2: Endpoint is immutable
- Attempt upgrade attacks
- Check for proxy patterns
- Verify no selfdestruct equivalents

INVARIANT 3: Only delegate or OApp can set configs
- Test unauthorized config changes
- Verify access control

INVARIANT 4: ULN is immutable
- Same as Endpoint immutability checks

INVARIANT 5: ULN owner CANNOT censor via native path
- Send message through native path
- Owner attempts to block
- Verify delivery

INVARIANT 6: DVN multisig security
- Test threshold requirements
- Attempt signature bypass
- Check role escalation

INVARIANT 7: DVN replay protection
- Submit same signature twice
- Cross-chain replay attempts
- Nonce bypass attempts

INVARIANT 8: Only Admin can execute signed payloads
- Test unauthorized execution
- Verify signature validation

INVARIANT 9: DVN permissionless admin grant
- Test valid signed payload admin grant
- Verify threshold requirements
```

---

## PHASE 5: STARKNET-SPECIFIC CHECKS (Days 11-12)

### 5.1 Storage Patterns
```
□ Storage slot collision risks
□ Storage exhaustion attacks
□ Felt252 overflow issues
□ Array length validation
```

### 5.2 Cairo Language Specifics
```
□ Felt arithmetic assumptions
□ Option/Result handling
□ Panic vs Result patterns
□ Trait implementation gaps
```

### 5.3 Dispatcher Risks
```
□ Dynamic dispatcher security
□ Interface mismatch attacks
□ Callback validation
□ Contract upgrade risks (despite immutability claim)
```

### 5.4 Starknet Syscalls
```
□ get_caller_address() spoofing
□ get_contract_address() assumptions
□ call_contract security
□ library_call risks
```

---

## PHASE 6: COMMON VULNERABILITY PATTERNS (Days 13-14)

### 6.1 Access Control
- [ ] Missing authorization checks
- [ ] Role confusion (admin vs owner vs delegate)
- [ ] Default permissions too broad
- [ ] Privilege escalation paths

### 6.2 Arithmetic & Logic
- [ ] Integer overflow/underflow (felt252)
- [ ] Division by zero
- [ ] Off-by-one errors
- [ ] Unchecked return values

### 6.3 Reentrancy
- [ ] Cross-function reentrancy
- [ ] Read-only reentrancy
- [ ] Composer callback reentrancy
- [ ] External call ordering

### 6.4 Cryptography
- [ ] Weak signature schemes
- [ ] Hash collision scenarios
- [ ] Nonce reuse
- [ ] Replay attacks

### 6.5 Economic
- [ ] Fee manipulation
- [ ] Token theft vectors
- [ ] Griefing attacks
- [ ] MEV extraction

---

## PHASE 7: REPORT PREPARATION (Days 15-16)

### 7.1 Finding Classification

**High Risk:**
- Loss of funds
- Protocol halt
- Censorship capability
- Invariant violations

**Medium Risk:**
- Griefing attacks
- DoS scenarios
- Configuration issues
- Non-critical invariant violations

**Low Risk (QA):**
- Gas optimization
- Code quality
- Best practices
- Informational

### 7.2 Report Structure
```markdown
## [H-01] Title

**Severity:** High/Medium/Low

**Description:**
Clear explanation of the vulnerability

**Impact:**
What can go wrong

**Proof of Concept:**
Code demonstrating the issue

**Recommended Mitigation:**
How to fix it

**References:**
- File: contract.cairo:123-145
- Related: Finding H-02
```

---

## KEY AREAS OF CONCERN (Per README)

### Priority 1: DVN/ULN Interaction
```
Files to focus:
- layerzero/src/message_lib/uln_302/ultra_light_node_302.cairo
- layerzero/src/workers/dvn/dvn.cairo

Questions:
- Can verification be bypassed?
- Are signatures properly validated?
- Replay protection sufficient?
```

### Priority 2: Storage Griefing
```
Files to focus:
- All storage operations in endpoint/
- message_lib storage patterns

Questions:
- Can attacker fill storage?
- DoS via storage exhaustion?
- Gas griefing vectors?
```

### Priority 3: Censorship Resistance
```
Files to focus:
- layerzero/src/endpoint/endpoint_v2.cairo (native payment path)
- Access control in all contracts

Questions:
- Can owner block messages under proper configs?
- Delegate abuse scenarios?
- ULN owner censorship paths?
```

---

## PRACTICAL AUDIT WORKFLOW

### Daily Routine:

**Morning (4 hours):**
1. Pick 2-3 files from current phase
2. Read code line-by-line
3. Take notes on suspicious patterns
4. Write proof-of-concept tests

**Afternoon (4 hours):**
1. Run tests for suspected issues
2. Trace execution paths
3. Document findings
4. Review related code

**Evening (1 hour):**
1. Review notes
2. Update finding list
3. Plan next day's files

---

## TOOLS & TECHNIQUES

### Static Analysis:
```bash
# Search for common patterns
grep -r "assert" layerzero/src/
grep -r "panic" layerzero/src/
grep -r "unwrap" layerzero/src/

# Find external calls
grep -r "call_contract" layerzero/src/
grep -r "library_call" layerzero/src/
```

### Dynamic Testing:
```bash
# Run specific tests
scarb test test_name

# Add debug prints
# Use println! in test functions
```

### Manual Review Checklist:
- [ ] Read function signature
- [ ] Check authorization
- [ ] Trace state changes
- [ ] Identify external calls
- [ ] Check return value handling
- [ ] Verify event emissions
- [ ] Test edge cases

---

## RISK ASSESSMENT FRAMEWORK

When evaluating findings, ask:

1. **Can this lead to loss of funds?** → High
2. **Can this halt the protocol?** → High
3. **Can this censor users?** → High
4. **Can this grief users?** → Medium
5. **Is this a best practice issue?** → Low

---

## FINAL CHECKLIST

Before submitting:
- [ ] All invariants tested
- [ ] Each in-scope file reviewed
- [ ] Findings properly categorized
- [ ] PoCs tested and working
- [ ] No known issues reported
- [ ] No out-of-scope findings
- [ ] Clear mitigation recommendations

---

## IMMEDIATE NEXT STEPS

**Step 1** (Today): Setup environment
```bash
cd /Users/franky/blockchain/audit/2025-10-layerzero/layerzero
scarb build
scarb test
```

**Step 2** (Tomorrow): Read the detailed layerzero/README.md and understand the architecture

**Step 3** (Days 3-14): Follow the systematic review phases above

**Step 4** (Days 15-16): Document and report findings

---

## CRITICAL FOCUS AREAS

1. **DVN/ULN Interaction** - Signature validation and replay protection
2. **Storage Griefing** - Starknet-specific DoS vectors
3. **Censorship Resistance** - Owner/delegate abuse prevention

---

## REMEMBER

- **High-risk findings downgraded = NO REWARDS** - Be accurate with severity
- Alexandria & Starknet core libs are **OUT OF SCOPE**
- Malformed byte array keccak bug is **KNOWN ISSUE**
- Focus on the 39 in-scope files
