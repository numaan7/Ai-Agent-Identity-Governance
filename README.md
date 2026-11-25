# AI Agent & Workload Identity Governance Scanner

A Python command-line scanner for reviewing application registrations and service principals in Microsoft Entra ID using Microsoft Graph.

## What it checks

- **Ownership:** flags applications without an assigned owner.
- **Permissions:** resolves Microsoft Graph app-role IDs and flags selected high-impact permissions, including `User.ReadWrite.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, and `Mail.ReadWrite`.
- **Credentials:** flags client secrets and certificates that expire within 90 days.
- **Identity Protection:** reports risky service principals when the tenant has the required Entra ID licensing.

Findings are marked `CRITICAL` when at least two risk flags apply, `MEDIUM` when one applies, and `COMPLIANT` when none apply. The scanner writes `nhi_governance_audit_report.json` in the current directory and prints a summary.

## Requirements

- Python 3
- A Microsoft Entra application registration with the Microsoft Graph **application permissions** listed below and admin consent
- Entra ID licensing that supports the Identity Protection risky service principal endpoint, if that check is required

The scanner uses these Graph application permissions:

| Permission | Purpose |
| --- | --- |
| `Application.Read.All` | Read application registrations, credentials, and application owners |
| `Directory.Read.All` | Read service principals and resolve app-role assignments |
| `IdentityRiskyServicePrincipal.Read.All` | Read risky service principal detections |

Grant only the permissions needed for your tenant and use of the scanner. The scanner does not make changes to directory objects.

## Setup and usage

```bash
git clone https://github.com/numaan7/Ai-Agent-Identity-Governance.git
cd Ai-Agent-Identity-Governance
python3 -m pip install requests python-dotenv
cp .env.example .env
```

Edit `.env` with the tenant ID, application (client) ID, and client secret for your scanner registration:

```dotenv
TENANT_ID=<your-tenant-id>
CLIENT_ID=<your-application-client-id>
CLIENT_SECRET=<your-client-secret>
```

Run the scanner:

```bash
python3 agent_governance_scanner.py
```

The generated report includes tenant identifiers, application names, owner information, permissions, and credential-expiry findings. Treat it as sensitive tenant data; it is excluded from Git by `.gitignore`. Keep `.env` private as well.

## Example output

The following is illustrative only; it does not contain results from a real tenant:

```text
[+] Audit complete! Audited 2 apps. Critical findings: 1
 - Example-App: [CRITICAL] Flags=['ORPHANED_NO_OWNER', 'EXCESSIVE_PRIVILEGE(User.ReadWrite.All)']
 - Example-Reader: [COMPLIANT] Flags=[]
```
