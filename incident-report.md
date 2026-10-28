# Incident Investigation Report — AWSRaid

## Executive summary
Splunk searches against the AWS CloudTrail CTF dataset identified suspicious authentication associated with `helpdesk.luke`, S3 object retrievals, a `PutBucketPublicAccessBlock` event for `backup-and-restore98825501`, and creation of `marketing.mark`, followed by its addition to `Admins`.

## Findings
1. `helpdesk.luke` was the suspected compromised identity in the challenge.
2. First displayed S3 `GetObject`: `2023-11-02 09:55:53`.
3. `Product2_CAD_Designs.dwg` was retrieved from `product-designs-repository31183937`.
4. A public-access-block configuration change was recorded for `backup-and-restore98825501`.
5. IAM user `marketing.mark` was created and added to `Admins`.

## Assessment
The combination of suspicious authentication, object access, bucket configuration changes, and privileged group membership warrants high-priority investigation. The screenshots show selected fields only. A public-access-block event alone does not establish that the bucket became public; the full event and effective bucket policy must be checked.

## Recommended actions
Preserve logs; verify login source and MFA; contain confirmed compromised identities; audit the new IAM user, access keys, policies, and group membership; inspect S3 public-access settings and bucket policies; assess accessed objects for sensitive data exposure.

## Limitations
Timestamps were transcribed from screenshots and timezone normalization was not independently confirmed. No raw CloudTrail export or challenge dataset is included.
