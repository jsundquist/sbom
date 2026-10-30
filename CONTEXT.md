# SBOM Dashboard

Dashboard for SBOMs and their vulnerabilities, with a separate worker that enriches packages.

## Language

**Owner**:
The single GitHub account, identified by its numeric user id, that may view the dashboard. Everyone else can sign in with GitHub but is shown nothing.
_Avoid_: Admin, user, viewer

**Upload token**:
A bearer secret the GitHub Action uses to upload an SBOM. It is separate from signing in and grants no read access.
_Avoid_: API key
