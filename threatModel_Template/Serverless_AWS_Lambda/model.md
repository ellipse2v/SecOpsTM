# Threat Model: Serverless — AWS Lambda Event-Driven Architecture

## Description
Event-driven serverless application on AWS. External clients reach the system via
Amazon API Gateway (REST + WebSocket). Business logic runs in Lambda functions.
Persistent state is split across DynamoDB (transactional), S3 (objects/uploads),
and Aurora Serverless (relational queries). An SQS/SNS fan-out bus decouples
producers from consumers. Secrets are stored in AWS Secrets Manager; short-lived
credentials are vended by STS (IAM roles). A WAF sits in front of API Gateway for
OWASP layer-7 filtering. CloudTrail and CloudWatch provide audit and observability.

## Context
gdaf_context = context/gdaf_context.yaml

## Boundaries
- **Internet / Clients**: color=lightcoral, isTrusted=False
- **Edge / CDN**: color=lightyellow, isTrusted=False, traversal_difficulty=medium
- **API Layer**: color=orange, isTrusted=False, traversal_difficulty=medium
- **Compute (Lambda VPC)**: color=lightgreen, isTrusted=True, traversal_difficulty=high
- **Data Stores**: color=lightblue, isTrusted=True, traversal_difficulty=high
- **Messaging / Event Bus**: color=lightsalmon, isTrusted=True, traversal_difficulty=medium
- **Security & Identity**: color=mediumpurple, isTrusted=True, traversal_difficulty=high
- **Observability**: color=lightgray, isTrusted=True, traversal_difficulty=medium

## Actors
- **End User (Browser/Mobile)**: boundary="Internet / Clients",
  description="Authenticated user interacting via REST API or WebSocket"
- **Third-Party Webhook**: boundary="Internet / Clients",
  description="External SaaS provider sending events (Stripe, GitHub, etc.)"
- **Developer / DevOps**: boundary="Internet / Clients",
  description="Engineer deploying via SAM / CDK / Serverless Framework"
- **Attacker**: boundary="Internet / Clients",
  description="External threat actor exploiting API endpoints or misconfigured IAM"

## Servers
- **CloudFront (CDN)**: boundary="Edge / CDN", type="cdn",
  description="CDN for static assets and API caching; geo-blocking and signed URLs enabled"
- **AWS WAF**: boundary="Edge / CDN", type="waf",
  description="Layer-7 WAF attached to CloudFront and API Gateway — OWASP ruleset + rate limiting",
  internet_facing=True
- **API Gateway (REST)**: boundary="API Layer", type="api_gateway",
  description="Amazon API Gateway REST API — request validation, JWT authorizer Lambda",
  internet_facing=True
- **API Gateway (WebSocket)**: boundary="API Layer", type="api_gateway",
  description="WebSocket API for real-time push (notifications, chat); connect/disconnect handlers"
- **Lambda — Auth Authorizer**: boundary="Compute (Lambda VPC)", type="faas",
  description="Custom JWT/OIDC authorizer — verifies Cognito tokens, returns IAM policy",
  credentials_stored=True
- **Lambda — API Handler**: boundary="Compute (Lambda VPC)", type="faas",
  description="Core business logic handler — reads/writes DynamoDB and Aurora; assumes task role",
  credentials_stored=True
- **Lambda — Event Consumer**: boundary="Compute (Lambda VPC)", type="faas",
  description="SQS consumer — processes async jobs (email, export, webhooks)"
- **Lambda — S3 Trigger**: boundary="Compute (Lambda VPC)", type="faas",
  description="Triggered on S3 PutObject — validates, transforms, and indexes uploaded files"
- **Lambda — Scheduled Job**: boundary="Compute (Lambda VPC)", type="faas",
  description="EventBridge cron — daily reports, cache warm-up, TTL-based cleanup"
- **DynamoDB**: boundary="Data Stores", type="database",
  description="Primary NoSQL store — on-demand capacity, point-in-time recovery, KMS CMK encryption"
- **Aurora Serverless v2 (PostgreSQL)**: boundary="Data Stores", type="database",
  description="Relational queries; auto-pause enabled, VPC-only, IAM auth + RDS Proxy",
  credentials_stored=True
- **S3 — Application Data**: boundary="Data Stores", type="object_storage",
  description="User-uploaded files; server-side KMS encryption, versioning, Object Lock for compliance"
- **S3 — Deployment Artifacts**: boundary="Data Stores", type="object_storage",
  description="Lambda ZIPs and CloudFormation templates — MFA delete, bucket policy deny public"
- **SQS Queue**: boundary="Messaging / Event Bus", type="message_queue",
  description="Standard SQS queue with DLQ; SSE-SQS encryption, VPC endpoint"
- **SNS Topic**: boundary="Messaging / Event Bus", type="message_broker",
  description="Fan-out to SQS subscribers and email/SMS; message filtering by attribute"
- **EventBridge (Scheduler)**: boundary="Messaging / Event Bus", type="scheduler",
  description="Cron and event-pattern rules; cross-account event bus bridging"
- **AWS Secrets Manager**: boundary="Security & Identity", type="secrets_manager",
  description="Stores DB passwords, API keys; auto-rotation via Lambda, resource policy",
  credentials_stored=True
- **AWS IAM / STS**: boundary="Security & Identity", type="iam",
  description="IAM roles with least-privilege policies; STS vends temporary credentials",
  credentials_stored=True
- **Amazon Cognito**: boundary="Security & Identity", type="identity_provider",
  description="User pools + identity pools — OIDC/SAML federation, MFA enforced",
  credentials_stored=True
- **CloudWatch Logs + Metrics**: boundary="Observability", type="monitoring",
  description="Centralised log aggregation for all Lambda functions; metric alarms"
- **CloudTrail**: boundary="Observability", type="audit",
  description="API audit trail — all management and data events, S3 integrity validation"
- **AWS Config**: boundary="Observability", type="compliance",
  description="Continuous compliance rules (no-public-S3, IAM-no-root-access-key, etc.)"

## Data
- **JWT / Cognito Tokens**: credentialsLife=SHORT, classification=SECRET,
  description="Short-lived OIDC tokens — 1h expiry, rotated on refresh"
- **IAM Temporary Credentials (STS)**: credentialsLife=SHORTLIVED, classification=SECRET,
  description="AssumeRole session tokens — max 1h TTL on Lambda execution roles"
- **Database Passwords (Secrets Manager)**: credentialsLife=LONG, classification=SECRET,
  description="Auto-rotated every 30 days; accessed at Lambda cold start"
- **User PII**: credentialsLife=NONE, classification=SENSITIVE,
  description="User profile, payment references stored in DynamoDB with field-level encryption"
- **Uploaded Files**: credentialsLife=NONE, classification=RESTRICTED,
  description="User uploads in S3 — AES-256 at rest, pre-signed URL access only"
- **Audit Logs (CloudTrail)**: credentialsLife=NONE, classification=INTERNAL,
  description="CloudTrail event logs — immutable, integrity-hash validated"
- **Lambda Environment Variables**: credentialsLife=UNKNOWN, classification=SECRET,
  description="Non-sensitive config via env vars; secrets referenced via Secrets Manager ARN"

## Dataflows
- **User API Request**: from="End User (Browser/Mobile)", to="AWS WAF", protocol="HTTPS"
- **WAF to API GW REST**: from="AWS WAF", to="API Gateway (REST)", protocol="HTTPS"
- **API GW to Authorizer**: from="API Gateway (REST)", to="Lambda — Auth Authorizer", protocol="Lambda Invoke"
- **Authorizer to Cognito**: from="Lambda — Auth Authorizer", to="Amazon Cognito", protocol="HTTPS"
- **API GW to Handler**: from="API Gateway (REST)", to="Lambda — API Handler", protocol="Lambda Invoke"
- **Handler to DynamoDB**: from="Lambda — API Handler", to="DynamoDB", protocol="HTTPS/AWS SDK"
- **Handler to Aurora**: from="Lambda — API Handler", to="Aurora Serverless v2 (PostgreSQL)", protocol="PostgreSQL/TLS"
- **Handler to SQS**: from="Lambda — API Handler", to="SQS Queue", protocol="HTTPS/AWS SDK"
- **Handler to Secrets Manager**: from="Lambda — API Handler", to="AWS Secrets Manager", protocol="HTTPS/AWS SDK"
- **SQS to Consumer**: from="SQS Queue", to="Lambda — Event Consumer", protocol="Lambda Invoke"
- **SNS fan-out to SQS**: from="SNS Topic", to="SQS Queue", protocol="HTTPS/AWS SDK"
- **S3 Event to Trigger Lambda**: from="S3 — Application Data", to="Lambda — S3 Trigger", protocol="Lambda Invoke"
- **EventBridge to Scheduled Job**: from="EventBridge (Scheduler)", to="Lambda — Scheduled Job", protocol="Lambda Invoke"
- **WebSocket Client**: from="End User (Browser/Mobile)", to="API Gateway (WebSocket)", protocol="WSS"
- **WebSocket to Handler**: from="API Gateway (WebSocket)", to="Lambda — API Handler", protocol="Lambda Invoke"
- **Webhook from Third Party**: from="Third-Party Webhook", to="AWS WAF", protocol="HTTPS"
- **Lambda to IAM/STS**: from="Lambda — API Handler", to="AWS IAM / STS", protocol="HTTPS/AWS SDK"
- **Lambda logs to CloudWatch**: from="Lambda — API Handler", to="CloudWatch Logs + Metrics", protocol="Internal AWS"
- **CloudTrail audit**: from="API Gateway (REST)", to="CloudTrail", protocol="Internal AWS"
- **Developer Deploy**: from="Developer / DevOps", to="S3 — Deployment Artifacts", protocol="HTTPS"
- **Attacker brute-force API**: from="Attacker", to="AWS WAF", protocol="HTTPS"
- **Attacker SSRF Lambda**: from="Attacker", to="Lambda — API Handler", protocol="Lambda Invoke"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTPS/AWS SDK**: color=darkgreen, line_style=solid
- **Lambda Invoke**: color=steelblue, line_style=dashed
- **PostgreSQL/TLS**: color=purple, line_style=solid
- **WSS**: color=teal, line_style=solid
- **Internal AWS**: color=grey, line_style=dotted
- **HTTP**: color=red, line_style=solid

## Severity Multipliers
- **AWS IAM / STS**: 2.0
- **AWS Secrets Manager**: 1.9
- **Lambda — Auth Authorizer**: 1.8
- **API Gateway (REST)**: 1.7
- **Aurora Serverless v2 (PostgreSQL)**: 1.6
- **DynamoDB**: 1.5
- **Lambda — API Handler**: 1.5
- **S3 — Application Data**: 1.4
- **Amazon Cognito**: 1.4

## Custom Mitre Mapping
- **IAM Privilege Escalation via Lambda Role**: tactics=["Privilege Escalation"], techniques=[{"id": "T1078", "name": "Valid Accounts"}, {"id": "T1098", "name": "Account Manipulation"}]
- **Lambda Event Injection (SQS/SNS payload)**: tactics=["Execution"], techniques=[{"id": "T1059", "name": "Command and Scripting Interpreter"}]
- **S3 Bucket Policy Misconfiguration**: tactics=["Collection", "Exfiltration"], techniques=[{"id": "T1530", "name": "Data from Cloud Storage Object"}]
- **Secrets Manager Exfiltration via Compromised Role**: tactics=["Credential Access"], techniques=[{"id": "T1528", "name": "Steal Application Access Token"}, {"id": "T1552", "name": "Unsecured Credentials"}]
- **SSRF to EC2 Metadata (IMDSv1)**: tactics=["Credential Access", "Discovery"], techniques=[{"id": "T1552", "name": "Unsecured Credentials"}, {"id": "T1190", "name": "Exploit Public-Facing Application"}]
- **Supply Chain via Deployment Bucket**: tactics=["Initial Access", "Persistence"], techniques=[{"id": "T1195", "name": "Supply Chain Compromise"}]
- **CloudTrail Disable / Log Tampering**: tactics=["Defense Evasion"], techniques=[{"id": "T1562", "name": "Impair Defenses"}]
- **Cognito Account Takeover**: tactics=["Initial Access"], techniques=[{"id": "T1078", "name": "Valid Accounts"}, {"id": "T1110", "name": "Brute Force"}]
- **Data Exfiltration via S3 Cross-Account Copy**: tactics=["Exfiltration"], techniques=[{"id": "T1537", "name": "Transfer Data to Cloud Account"}]
