# Firewall Policy Engine (FPE)

**Firewall Policy Engine (FPE)** is a Python-based GUI application for editing, validating, analyzing, versioning, simulating, and deploying Linux **nftables** firewall policies.

FPE is designed around a controlled firewall-management workflow that separates:

```text
Edit
  ↓
Validate
  ↓
Security Analysis
  ↓
Simulate / Review
  ↓
Confirm
  ↓
Final Validation
  ↓
Privileged Deployment
  ↓
Audit
```

The project is intended primarily for **cybersecurity learning, research, defensive security engineering, and Linux firewall experimentation**.

> **Important:** Real firewall deployment can interrupt network connectivity or lock you out of a system. Test real deployments in a Linux virtual machine or another environment where you have console access.

---

## Features

### Policy Editor

* GUI-based nftables ruleset editor
* Real-time ruleset preview
* Built-in example nftables policy
* Save policies as versions
* Load previously saved policies
* Delete saved versions

### nftables Validation

FPE uses nftables' **check mode** for non-destructive validation:

```bash
nft -c -f -
```

The candidate ruleset is supplied to nftables through standard input.

The `-c` option tells nftables to check the configuration without applying it.

This allows FPE to distinguish between:

```text
Valid nftables configuration
```

and:

```text
Invalid nftables configuration
```

The validation step does **not** replace security analysis. A ruleset can be valid according to nftables while still being overly permissive or risky.

---

## Security Analysis

FPE includes an advisory security-analysis layer that examines the candidate policy for potentially risky configurations.

Current checks include:

* Empty policies
* Missing nftables table declarations
* Missing input chains
* `policy accept` on input chains
* Drop policies without an obvious SSH acceptance rule
* Broad SSH exposure
* Broad RDP exposure
* Broad VNC exposure
* Unrestricted network ranges
* Established/related connection rules
* Loopback rules
* Potentially destructive nftables operations

Findings are reported using severity levels:

```text
CRITICAL
HIGH
MEDIUM
INFO
```

Example:

```text
[HIGH] Input chain 'input' uses policy accept.

[HIGH] SSH port 22 appears accepted without a
       source-address restriction.

[INFO] Input chain 'input' permits established/related traffic.
```

### Important limitation

The security analyzer is **advisory**.

It is not a complete nftables parser and does not mathematically prove that a firewall policy is secure.

In particular, it does not guarantee:

* SSH connectivity
* Absence of firewall lockouts
* Correct rule precedence in every possible policy
* Absence of conflicting rules
* Complete detection of dangerous configurations
* Overall firewall security

The authoritative syntax and semantic validation is performed by nftables itself.

---

## Deployment Safety

Real deployment is intentionally separated from validation.

The deployment workflow is:

```text
Candidate Policy
      ↓
nftables Check
      ↓
Security Analysis
      ↓
Security Warning Review
      ↓
User Confirmation
      ↓
Final nftables Check
      ↓
sudo nft -f -
```

The final validation is performed against the same policy snapshot that is subsequently deployed.

Actual deployment uses:

```bash
sudo nft -f -
```

The application does not run the entire GUI as root.

Only the actual firewall deployment operation requires elevated privileges.

---

## Demo Mode

FPE includes a demo mode for safe experimentation:

```bash
python app.py --demo
```

Demo mode does not make changes to the system firewall.

It is recommended for:

* Learning the interface
* Testing policy analysis
* Demonstrating the project
* Testing the versioning system
* Testing the audit interface
* Experimenting without a real nftables deployment

---

## Real Deployment Mode

Real deployment is started with:

```bash
python app.py
```

Real deployment requires:

* Linux
* nftables
* Appropriate sudo privileges
* A system where firewall changes can safely be tested

Before using real deployment, ensure that you have console access to the machine.

A firewall configuration can unintentionally block:

* SSH
* Remote administration
* Network services
* Application traffic
* Management interfaces

---

# Policy Versioning

FPE stores policies locally using SQLite.

Each saved policy contains:

* Policy ID
* Policy name
* Ruleset content
* Creation timestamp
* SHA-256 content hash

The application provides:

```text
Load
Delete
```

controls for stored policy versions.

The database is automatically created when FPE starts.

Default database:

```text
policies_customtk.db
```

### Policy hashes

FPE calculates a SHA-256 hash for policy content.

This allows audit records to associate an operation with a specific policy content snapshot.

The hash provides **integrity identification**, but the SQLite database itself is not tamper-proof.

---

# Audit Logging

FPE maintains an application-level audit log.

Tracked operations include:

* Policy saves
* UI saves
* Validation attempts
* Security analysis
* Simulations
* Deployment attempts
* Successful deployments
* Failed deployments
* Blocked deployments
* Aborted deployments
* Policy deletions

Audit records include information such as:

```text
Timestamp
Action
Policy ID
Policy hash
Details
```

Example:

```text
[2026-09-20T10:30:00+00:00]
deploy
pid=42
hash=8f13a0c5d921
Deployment succeeded
```

### Audit limitation

The audit system is an **application-level audit log stored in SQLite**.

It is not designed to be tamper-resistant against someone who has direct access to the database.

---

# Database Migration

FPE includes a lightweight SQLite schema migration mechanism.

This is important when upgrading from an older version of FPE.

For example, if an existing database does not contain the newer:

```text
content_hash
```

columns, FPE detects the missing columns and adds them automatically.

Existing policy and audit data can therefore be retained during normal upgrades.

---

# Requirements

## Software

* Python 3.8+
* CustomTkinter
* SQLite
* Linux nftables for real deployment
* sudo privileges for real deployment

Install the Python dependency:

```bash
pip install -r requirements.txt
```

Or:

```bash
pip install customtkinter
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/ShahazaadAhmed/Firewall-Policy-Engine-FPE-.git
```

Enter the project directory:

```bash
cd Firewall-Policy-Engine-FPE-
```

Create a virtual environment if desired:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Running FPE

## Demo Mode

```bash
python app.py --demo
```

Use this mode when you want to explore the application without making real firewall changes.

## Real Mode

```bash
python app.py
```

Real deployment requires Linux, nftables, and sudo access.

---

# Using FPE

## 1. Edit

Enter an nftables ruleset into the editor.

A sample ruleset is provided when the application starts.

---

## 2. Validate

Click:

```text
Validate
```

FPE performs:

```bash
nft -c -f -
```

This checks the candidate ruleset without applying it.

A successful validation means nftables accepted the configuration for checking.

It does **not** mean the firewall policy is secure.

---

## 3. Analyze

Click:

```text
Analyze
```

FPE performs its advisory security analysis.

Potential findings are displayed with severity levels.

---

## 4. Simulate

Click:

```text
Simulate
```

Simulation combines:

* nftables validation
* FPE security analysis
* Policy/audit recording

Demo mode can be used to safely demonstrate the workflow.

---

## 5. Save

Click:

```text
Save Version
```

The current ruleset is stored in SQLite.

A SHA-256 hash is also generated for the policy.

---

## 6. Deploy

Click:

```text
Deploy
```

FPE first validates the ruleset.

If high-risk findings are detected, the application displays them before continuing.

The user must explicitly confirm deployment.

FPE then performs a final validation before executing:

```bash
sudo nft -f -
```

If deployment succeeds, the deployed policy is stored as a version and the operation is recorded in the audit log.

---

# Testing

Automated tests are included in:

```text
tests/
└── test_fpe.py
```

Run them with:

```bash
python -m unittest discover -s tests -v
```

The current tests cover areas such as:

* Empty policy detection
* Permissive input policies
* SSH safety analysis
* Restricted SSH rules
* Comment handling
* SHA-256 policy hashing
* SQLite policy storage

Tests involving actual nftables should be performed separately on an appropriate Linux test environment.

---

# Linux Setup

For Ubuntu/Debian-based systems:

```bash
sudo apt update
sudo apt install nftables
```

Verify nftables:

```bash
nft --version
```

Check whether sudo can execute nftables:

```bash
sudo nft list ruleset
```

For real deployment, use a test machine or virtual machine whenever possible.

---

# Project Structure

```text
.
├── app.py
├── README.md
├── requirements.txt
├── tests/
│   └── test_fpe.py
├── .gitignore
└── policies_customtk.db
```

`policies_customtk.db` is generated automatically and should not normally be committed to Git.

---

# Architecture

The current application follows this conceptual architecture:

```text
                    ┌──────────────────────┐
                    │       FPE GUI        │
                    │    CustomTkinter     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Policy Snapshot    │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
       ┌──────────────────┐       ┌──────────────────┐
       │ nftables Check   │       │ Security Analysis│
       │   nft -c -f -    │       │ Advisory Checks  │
       └────────┬─────────┘       └────────┬─────────┘
                │                          │
                └────────────┬─────────────┘
                             ▼
                   ┌─────────────────────┐
                   │ User Confirmation   │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Final Validation    │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Privileged Deploy   │
                   │   sudo nft -f -     │
                   └──────────┬──────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
        ┌─────────────────┐       ┌─────────────────┐
        │ SQLite Policy   │       │ Audit Logging   │
        │ Versions/Hashes │       │ Actions/Hashes  │
        └─────────────────┘       └─────────────────┘
```

---

# How FPE Works Internally

## 1. Policy Input

The user creates or loads an nftables ruleset through the GUI.

The application keeps the exact policy content as a snapshot for validation and deployment.

---

## 2. nftables Validation

FPE sends the policy to:

```bash
nft -c -f -
```

This is nftables check mode.

The ruleset is not intentionally applied during this step.

---

## 3. Security Analysis

FPE performs additional advisory checks.

This layer exists because:

```text
nftables-valid
```

does not necessarily mean:

```text
security-appropriate
```

For example, an input chain with:

```nft
policy accept;
```

can be valid nftables syntax while being much more permissive than intended.

---

## 4. Deployment

After validation, analysis, and explicit user confirmation:

```bash
sudo nft -f -
```

is used to apply the ruleset.

---

## 5. Versioning

Policies are stored in SQLite with their content and SHA-256 hash.

This provides a local history of configurations used by the application.

---

## 6. Auditing

Important application events are recorded with timestamps, actions, policy IDs, details, and policy hashes.

---

# Security Design Principles

FPE is built around several defensive-security principles:

### Least Privilege

The GUI itself does not require root privileges.

Elevated privileges are used only for the actual nftables deployment command.

### Defense in Depth

FPE does not rely on a single check.

The deployment path uses:

```text
nftables validation
+
FPE security analysis
+
user confirmation
+
final validation
```

### Fail Closed on Validation

If nftables rejects the candidate configuration, deployment is blocked.

### Explicit User Confirmation

Firewall deployment is an intentional user action rather than an automatic background operation.

### Configuration Traceability

Policies are versioned and associated with SHA-256 content hashes.

### Auditability

Important policy-management operations are recorded locally.

---

# Current Limitations

FPE is a portfolio/educational project and should not currently be considered a replacement for enterprise firewall-management platforms.

Known limitations include:

* No complete nftables parser
* Security analysis is heuristic/advisory
* No formal policy verification
* No automatic firewall rollback
* No automatic SSH connectivity verification
* No tamper-resistant audit storage
* No distributed policy management
* No multi-user access-control system
* No centralized logging
* No high-availability deployment mechanism

These limitations are intentional areas for future development rather than claims of functionality that the current implementation does not provide.

---

# Future Development

Potential future improvements include:

* Full nftables policy parser
* Rule precedence analysis
* Conflict detection
* More comprehensive management-port exposure analysis
* Policy diffing
* Automated rollback
* Pre-deployment firewall snapshots
* Stronger automated testing
* Linux CI testing
* Static analysis and security scanning
* Policy import/export
* Structured policy templates
* Centralized audit logging
* Role-based access control
* More comprehensive nftables semantic analysis

---

# Security Testing Recommendations

When testing real deployment:

1. Use a virtual machine where possible.
2. Keep console access available.
3. Test policies in demo/check mode first.
4. Validate the candidate ruleset.
5. Review security-analysis warnings.
6. Keep a known-good policy available.
7. Avoid experimenting with firewall policies on a remotely accessible production machine.

---

# Disclaimer

This software is provided for **educational and research purposes**.

The author does not guarantee that FPE will prevent firewall misconfiguration, network lockout, security incidents, or other unintended consequences.

Users are responsible for reviewing and understanding firewall policies before applying them to systems they control.

Do not use the software to interfere with systems without authorization.

---

# Contributing

Contributions and improvements are welcome.

Areas that would be particularly useful include:

* Improving nftables policy analysis
* Adding comprehensive tests
* Improving deployment safety
* Adding rollback mechanisms
* Improving documentation
* Adding policy templates
* Improving the GUI
* Adding Linux CI testing
* Improving audit functionality

When contributing security-related changes, tests should be included where practical.

---

# License

This project is licensed under the **MIT License**.

See the `LICENSE` file for the full license text.
