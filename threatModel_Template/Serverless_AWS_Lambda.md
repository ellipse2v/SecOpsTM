# Serverless — AWS Lambda Event-Driven Architecture — Quick Reference

See the full model with GDAF context in `Serverless_AWS_Lambda/model.md`.

## Architecture Summary
- **Edge / CDN**: CloudFront + AWS WAF (OWASP ruleset, rate limiting)
- **API Layer**: API Gateway REST + WebSocket (JWT authorizer)
- **Compute (Lambda VPC)**: Auth Authorizer, API Handler, Event Consumer, S3 Trigger, Scheduled Job
- **Data Stores**: DynamoDB, Aurora Serverless v2, S3 (application data + deployment artifacts)
- **Messaging**: SQS + SNS fan-out, EventBridge scheduler
- **Security & Identity**: Secrets Manager, IAM/STS, Cognito
- **Observability**: CloudWatch, CloudTrail, AWS Config

## Key Threats Covered
- IAM privilege escalation via over-permissive Lambda execution role
- SSRF to EC2 instance metadata (IMDSv1) → STS credential theft
- S3 bucket policy misconfiguration → public data exposure / PII leak
- Lambda event injection via crafted SQS/SNS message (business logic bypass)
- Secrets Manager exfiltration via compromised role
- Supply chain compromise via S3 deployment bucket
- CloudTrail disable / log tampering (defense evasion)
- Cognito account takeover (credential stuffing, brute force)
- Cross-account S3 exfiltration via misconfigured bucket replication

## Usage
```bash
secopstm --model-file threatModel_Template/Serverless_AWS_Lambda/model.md \
         --output-format all --navigator
```
