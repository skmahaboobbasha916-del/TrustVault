# TrustVault – AI Usage Log

This document records how AI tools supported the development of TrustVault. AI assistance was used for guidance, code review, debugging, and test improvements. All generated code was reviewed and tested as part of development.

Tools used:
- ChatGPT (OpenAI)
- Codex extension

## 1. Project Architecture

**Date:** 2026-11-07  
**Tool:** ChatGPT  
**Prompt summary:** Help design TrustVault, a secure document-sharing application, with Flask, MySQL, authentication, document management, and audit logging.  
**Contribution:** Helped plan the application structure, database tables, routes, controllers, and models.

## 2. Document Upload and Validation

**Date:** 2026-11-07  
**Tool:** ChatGPT and Codex  
**Prompt summary:** Help implement secure document uploads with file validation and database storage.  
**Contribution:** Assisted with upload logic, file validation, and error handling. The feature was tested through the application.

## 3. Authorization and Access Control

**Date:** 2026-11-08  
**Tool:** ChatGPT and Codex  
**Prompt summary:** Review authorization requirements for document owners, READ users, EDIT users, and administrators. Ensure permissions are checked on the server for every protected action.  
**Contribution:** Assisted with authorization-service design and access-control tests. The implementation restricts actions according to the user's actual permissions.

## 4. Audit Logging and Permission Decisions

**Date:** 2026-11-08  
**Tool:** ChatGPT and Codex  
**Prompt summary:** Help implement audit records for document access and permission changes, including successful and denied actions.  
**Contribution:** Assisted with audit-event recording and verification of permission-related audit entries.

## 5. Document Sharing and Revocation

**Date:** 2026-11-09  
**Tool:** ChatGPT and Codex  
**Prompt summary:** Help implement document permission granting and revocation, including the sharing interface and server-side checks.  
**Contribution:** Assisted with the grant/revoke routes, sharing page, and permission handling. Granting and revocation were manually tested.

## 6. Automated Testing and Debugging

**Date:** 2026-11-09  
**Tool:** ChatGPT and Codex  
**Prompt summary:** Help identify and fix failing document-route tests and review the final changes.  
**Contribution:** Assisted with debugging and test corrections. The final recorded test run completed with **211 tests passed**.

## Responsible AI Usage

- AI tools were used as development assistants, not as replacements for developer responsibility.
- Generated suggestions were reviewed and tested.
- Authorization decisions are enforced by application code, not by AI.
- AI tools are not treated as trusted sources of permission or access decisions.
- The developer remains responsible for the final implementation, testing, and submission.