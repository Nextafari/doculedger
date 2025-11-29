#DocuLedger

This repository contains the **backend services and smart contracts** for a **blockchain-powered project management application** designed to **securely track, verify, and audit approval workflows across projects**.

The system enables organizations to manage project documents, approvals, and sign-offs in a **transparent and tamper-resistant manner** by combining **off-chain storage** with **on-chain verification**. Project documents are stored off-chain for efficiency, while cryptographic hashes, approval events, and workflow state changes are recorded on the blockchain to provide **immutability, traceability, and accountability**.

The backend exposes APIs for managing projects, documents, users, approval states, and notifications, and integrates with smart contracts to ensure that every approval action is **permanently recorded and verifiable**. This architecture supports compliance, reduces disputes, and strengthens trust between stakeholders involved in multi-party project execution.

#### Key Objectives

* Ensure **end-to-end traceability** of project approvals
* Prevent **unauthorized alteration** of approved documents
* Provide **auditable approval histories** for compliance and governance
* Support scalable enterprise project workflows using blockchain technology

#### Technology Scope

* Backend API for project, document, and approval management
* Smart contracts for recording approval events and document hashes
* Hybrid storage model (off-chain documents + on-chain proofs)
* Designed for integration with modern web frontends and analytics dashboards

---
