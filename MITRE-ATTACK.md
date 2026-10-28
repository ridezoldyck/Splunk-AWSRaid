# Potential MITRE ATT&CK Mapping

These are tentative mappings for portfolio analysis, not proof of adversary intent.

| Observed behavior | Potential technique | Rationale |
|---|---|---|
| Repeated authentication failures | T1110 — Brute Force | Validate sequence and source context |
| New IAM user created | T1136.003 — Create Account: Cloud Account | Cloud account creation may support persistence |
| User added to `Admins` | T1098 — Account Manipulation | Group membership can alter privileges |
| S3 object retrieval | T1530 — Data from Cloud Storage | Relevant if an adversary accessed cloud-stored data |
| S3 public-access-block modification | Requires further validation | Review exact configuration change before mapping |

Re-check current ATT&CK documentation before using these mappings in formal reports.
