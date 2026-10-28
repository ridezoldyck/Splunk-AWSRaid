# AWSRaid — AWS CloudTrail Investigation

**Portfolio:** Junior SOC Analyst / Blue Team | **Tools:** Splunk, AWS CloudTrail, SPL  
**Lab:** CyberDefenders AWSRaid CTF

## Summary
Investigated suspicious AWS authentication and subsequent CloudTrail activity. The captured Splunk results show suspected account `helpdesk.luke`, S3 object retrievals, a bucket public-access-block configuration change, and creation of an IAM user that was added to an administrative group.

## Key findings

| Finding | Result |
|---|---|
| Suspected compromised identity | `helpdesk.luke` |
| First S3 `GetObject` in captured results | `2023-11-02 09:55:53` |
| Bucket containing a DWG file | `product-designs-repository31183937` |
| Bucket with `PutBucketPublicAccessBlock` event | `backup-and-restore98825501` |
| Newly created IAM user | `marketing.mark` |
| Group membership change | `marketing.mark` added to `Admins` |

**Caution:** `PutBucketPublicAccessBlock` proves that the setting was modified, not by itself that public access was enabled. Confirm the request parameters, bucket policy, ACLs, and account-level settings. Timestamps are transcribed from screenshots; verify timezone before external correlation.

## Investigation queries

### Failed authentication by username
```spl
index="aws_cloudtrail" eventSource="signin.amazonaws.com" errorMessage="Failed authentication"
| stats count by userIdentity.userName
| sort -count
```

### Sign-in history
```spl
index="aws_cloudtrail" eventSource="signin.amazonaws.com" "userIdentity.userName"="helpdesk.luke"
| table _time userIdentity.userName errorMessage responseElements.ConsoleLogin sourceIPAddress
| sort _time
```

### S3 object retrievals
```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject"
| table _time eventName requestParameters.bucketName requestParameters.key
| sort _time
```

### DWG file
```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" "*.dwg"
| table _time requestParameters.bucketName requestParameters.key
```

### Public-access-block change
```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName="PutBucketPublicAccessBlock"
| table _time requestParameters.bucketName userIdentity.arn
```

### IAM user creation
```spl
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventCategory="Management"
| search eventName="CreateUser" OR eventName="CreateLoginProfile"
| table _time eventName requestParameters.userName
| sort _time
```

### Group membership change
```spl
index="aws_cloudtrail" eventName="AddUserToGroup"
| table _time requestParameters.groupName requestParameters.userName
```

## Timeline from screenshots

| Timestamp shown | Observation |
|---|---|
| `2023-11-02 09:55:53` | First displayed S3 `GetObject` |
| `2023-11-02 09:56:07` | `Product2_CAD_Designs.dwg` retrieved |
| `2023-11-02 09:58:01` | `PutBucketPublicAccessBlock` on `backup-and-restore98825501` |
| `2023-11-02 09:59:38` | `marketing.mark` added to `Admins` |

## Assessment and response recommendations
- Validate whether the login was authorized; review source IP, MFA, user agent, and session context.
- Preserve CloudTrail events and surrounding logs.
- Contain confirmed compromised identities and revoke sessions/credentials as appropriate.
- Audit `marketing.mark`, its access keys, policies, and group memberships.
- Review the full S3 configuration event, bucket policies, ACLs, and access logs to confirm exposure and impact.
- Investigate accessed objects for sensitivity and possible data exfiltration.

## Skills demonstrated
Splunk SPL, CloudTrail analysis, authentication triage, S3 access investigation, IAM persistence and privilege-change analysis, timeline building, incident reporting.

## Evidence
Screenshots of the Splunk results are in [`evidence/`](evidence/).

## Disclaimer
This is a learning exercise based on a deliberately constructed CTF dataset, not evidence of activity in a real AWS account. Do not publish raw datasets, credentials, or session tokens.
