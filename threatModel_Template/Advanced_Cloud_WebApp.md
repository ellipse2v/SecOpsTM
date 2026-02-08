# Threat Model: Advanced Cloud Web Application

## Description
This model describes a modern, cloud-native web application with a microservices architecture, hosted in a cloud environment. It includes a public-facing zone, a private application zone, and a secure data zone, demonstrating the use of advanced component attributes for detailed threat analysis.

## Boundaries
- **Public Cloud Zone**: 
  type=network-cloud-provider,
  isTrusted=False, 
  isFilled=True,
  color=lightcoral
- **Private App Zone**: 
  type=network-cloud-security-group,
  isTrusted=True, 
  isFilled=True,
  color=khaki
- **Secure Data Zone**: 
  type=network-cloud-security-group,
  isTrusted=True, 
  isFilled=True,
  color=lightblue

## Actors
- **End User**: 
  boundary="Public Cloud Zone", 
  authenticity=credentials, // User logs in with username/password
  isTrusted=False
- **DevOps Engineer**:
  boundary="Public Cloud Zone",
  authenticity=two-factor, // Engineer requires MFA
  isTrusted=True

## Servers
- **CDN Load Balancer**:
  boundary="Public Cloud Zone",
  type=load-balancer,
  health_check_enabled=True,
  tags=[aws-alb]
- **API Gateway**:
  boundary="Public Cloud Zone",
  type=api-gateway,
  machine=serverless,
  redundant=True,
  confidentiality=medium,
  integrity=medium,
  availability=high
- **Auth Service**:
  boundary="Private App Zone",
  type=auth-server,
  machine=container,
  auth_protocol=oidc,
  mfa_enabled=True,
  tags=[keycloak, docker]
- **Product Microservice**:
  boundary="Private App Zone",
  machine=container,
  redundant=True,
  confidentiality=high,
  integrity=high,
  availability=high,
  tags=[spring-boot, java, docker]
- **Product Database**:
  boundary="Secure Data Zone",
  type=database,
  machine=virtual, // e.g., AWS RDS instance
  database_type=sql,
  encryption=data-with-symmetric-shared-key, // Encryption at rest
  backup_frequency=daily,
  redundant=True,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  tags=[postgresql, rds]
- **CI/CD Server**:
  boundary="Private App Zone",
  type=management-server,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=medium,
  tags=[jenkins, groovy]

## Data
- **User Credentials**:
  description="User login credentials (username/password hash)",
  classification=SECRET,
  confidentiality=critical,
  integrity=critical,
  availability=high
- **API Request**:
  description="Authenticated API request from the frontend to a microservice",
  classification=RESTRICTED,
  confidentiality=high,
  integrity=high,
  availability=medium
- **Database Transaction**:
  description="A read/write transaction to the product database.",
  classification=SECRET,
  confidentiality=critical,
  integrity=critical,
  availability=high
- **Deployment Script**:
  description="A script used by the CI/CD server to deploy a microservice.",
  classification=SECRET,
  confidentiality=critical,
  integrity=critical,
  availability=medium

## Dataflows
- **UserToGateway**:
  from="End User",
  to="API Gateway",
  protocol=HTTPS,
  data="API Request",
  authentication=token, // JWT
  authorization=enduser-identity-propagation,
  is_encrypted=True
- **GatewayToAuth**:
  from="API Gateway",
  to="Auth Service",
  protocol=HTTPS,
  data="User Credentials",
  authentication=token,
  authorization=technical-user,
  is_encrypted=True
- **GatewayToProductSvc**:
  from="API Gateway",
  to="Product Microservice",
  protocol=HTTPS,
  data="API Request",
  authentication=token,
  authorization=enduser-identity-propagation,
  is_encrypted=True
- **ProductSvcToDB**:
  from="Product Microservice",
  to="Product Database",
  protocol=TCP,
  data="Database Transaction",
  authentication=credentials, // DB username/password
  authorization=technical-user,
  is_encrypted=False // Traffic is inside a trusted, secure zone
- **DevOpsToCICD**:
  from="DevOps Engineer",
  to="CI/CD Server",
  protocol=SSH,
  data="Deployment Script",
  authentication=two-factor, // SSH key + password
  authorization=enduser-identity-propagation,
  vpn=True,
  ip_filtered=True,
  is_encrypted=True
- **CICDToProductSvc**:
  from="CI/CD Server",
to="Product Microservice",
protocol=SSH,
data="Deployment Script",
authentication=credentials,
authorization=technical-user,
is_encrypted=True
