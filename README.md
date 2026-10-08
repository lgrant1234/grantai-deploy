# GrantAi system of record for AI agents: deploy into your own Azure tenant

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flgrant1234%2Fgrantai-deploy%2Fmain%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Flgrant1234%2Fgrantai-deploy%2Fmain%2Fportal%2FcreateUiDefinition.json)

One deployment, about 25 minutes, no vendor access: a collector VM from a community gallery image,
a private Postgres server, a Key Vault, an immutable cold-storage container, and a first-boot
self-check. Nothing leaves your tenant except the licence check. The 30-day trial is Enterprise tier;
when it ends, reads continue and writes stop until a licence key is loaded.

## What gets deployed

- Virtual network with a private subnet for Postgres; network security group admitting the service
  port only from the client range you give (bearer authentication applies as well).
- Collector VM (Trusted Launch, system-assigned identity) from the community gallery image
  `grantai-655c6c15-1c00-4d85-aa47-d8e1b0ed5e38` (Ubuntu 22.04 LTS; Red Hat Enterprise Linux 9 is available through a private gallery share, since Azure does not allow images derived from a marketplace image with a billing plan in community galleries), running the GrantAi server, the Foundry tap and the reviewer.
- Postgres Flexible Server (private access, auto-grow), Key Vault (RBAC, purge protection) holding
  the bootstrap token, the install identity, the export signing key and the licence, a storage
  account with the immutable `audit-cold` container (7-year policy, unlocked).
- Optional: public IP with a Let's Encrypt certificate; Azure AI Foundry capture; reviewer webhook.

## After it finishes

The deployment's outputs tell you the console address and where the bearer token is:

    az keyvault secret show --vault-name <keyVaultName> -n grantai-http-token --query value -o tsv

Open `https://<fqdn>:8443/audit`, sign in with the token, and use the Records, Callers, Findings
and Export tabs. To capture Azure AI Foundry agents, grant the collector VM's identity the
**Foundry User** role on your project (one role assignment) if you did not pass the project endpoint
at deployment, then redeploy with it set.

## Verify an export without GrantAi software

    python3 tools/grantai-verify-bundle.py grantai-export-<time>.json --trust-fingerprint <sha256 from the collector's /health>

Needs only Python 3 and OpenSSL. It checks the signature, walks the hash chain from genesis and
re-hashes every record; altered content, a removed chain row or a wrong key each fail with the reason.

## Files

- `mainTemplate.json`: the ARM template (compiled from Bicep in the product repository).
- `portal/createUiDefinition.json`: the portal form.
- `boot/2.0.1/`: the first-boot files the VM fetches (checksums in `SHA256SUMS`).
- `tools/grantai-verify-bundle.py`: the offline verifier.

Requirements in the target subscription: permission to create role assignments (Owner or
User Access Administrator on the resource group), and 2 free vCPUs in the region.
