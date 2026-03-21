# Threat Model: EcoShop — Order Service Cluster

## Description
The Order Service is an event-driven microservices cluster responsible for the full order
lifecycle: intake, payment processing, shipping coordination, and customer notification.
An AMQP message queue (RabbitMQ) decouples order intake from downstream processing.

Two payment service instances process card transactions against the payment gateway
(external, PCI-DSS L1). Two shipping service instances coordinate with the logistics
provider API. A notification service dispatches transactional emails and SMS.

All services are PCI-DSS in-scope due to proximity to payment data. Card numbers are
never stored — only payment tokens are persisted.

## Context
bom_directory = BOM

## Boundaries
- **Order Processing Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightcyan,
  traversal_difficulty=medium,
  businessValue="Event-driven order processing — PCI-DSS in-scope"
- **Payment Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=high,
  businessValue="Payment services — strict PCI-DSS controls, no card number persistence"

## Servers
- **OrderQueue**:
  boundary="Order Processing Zone",
  type=message-queue,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=credentials,
  encryption=TLS,
  tags=[rabbitmq, amqp, durable, clustered],
  businessValue="RabbitMQ cluster — durable order queue, dead-letter exchange",
  entry_point=True
- **PaymentService_1**:
  boundary="Payment Zone",
  type=application-server,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  credentials_stored=False,
  tags=[pci-dss, payment-tokenization, stripe, active],
  businessValue="Payment processor — tokenizes card data, calls Stripe API"
- **PaymentService_2**:
  boundary="Payment Zone",
  type=application-server,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  credentials_stored=False,
  tags=[pci-dss, payment-tokenization, stripe, standby],
  businessValue="Payment processor — active-active standby"
- **ShippingService_1**:
  boundary="Order Processing Zone",
  type=application-server,
  machine=virtual,
  confidentiality=medium,
  integrity=high,
  availability=high,
  redundant=True,
  mfa_enabled=False,
  auth_protocol=credentials,
  encryption=TLS,
  tags=[shipping, logistics-api, active],
  businessValue="Shipping coordinator — calls logistics provider REST API"
- **ShippingService_2**:
  boundary="Order Processing Zone",
  type=application-server,
  machine=virtual,
  confidentiality=medium,
  integrity=high,
  availability=high,
  redundant=True,
  mfa_enabled=False,
  auth_protocol=credentials,
  encryption=TLS,
  tags=[shipping, logistics-api, standby],
  businessValue="Shipping coordinator — standby instance"
- **NotificationService**:
  boundary="Order Processing Zone",
  type=application-server,
  machine=virtual,
  confidentiality=medium,
  integrity=medium,
  availability=medium,
  redundant=False,
  mfa_enabled=False,
  auth_protocol=credentials,
  encryption=TLS,
  credentials_stored=True,
  tags=[email, sms, sendgrid, twilio, transactional],
  businessValue="Notification dispatcher — sends order emails and SMS via SendGrid and Twilio"

## Data
- **Order**:
  description="Validated order payload — product IDs, quantities, customer reference (no payment data)",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True,
  pii=False
- **PaymentInfo**:
  description="Payment intent reference and card indicator — NOT raw PAN (tokenized upstream)",
  classification=SECRET,
  encrypted_in_transit=True,
  encrypted_at_rest=False,
  pii=False,
  dpia=False
- **ShippingDetails**:
  description="Customer shipping address and contact — GDPR personal data",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True,
  pii=True,
  dpia=True
- **NotificationRequest**:
  description="Transactional notification payload — order status, tracking number, customer email",
  classification=RESTRICTED,
  encrypted_in_transit=True,
  pii=True

## Dataflows
- **QueueToPayment1**:
  from=OrderQueue,
  to=PaymentService_1,
  protocol=AMQP,
  port=5672,
  authentication=credentials,
  encryption=TLS,
  data=Order
- **QueueToPayment2**:
  from=OrderQueue,
  to=PaymentService_2,
  protocol=AMQP,
  port=5672,
  authentication=credentials,
  encryption=TLS,
  data=Order
- **Payment1ToShipping1**:
  from=PaymentService_1,
  to=ShippingService_1,
  protocol=AMQP,
  port=5672,
  authentication=credentials,
  encryption=TLS,
  data=PaymentInfo
- **Payment2ToShipping2**:
  from=PaymentService_2,
  to=ShippingService_2,
  protocol=AMQP,
  port=5672,
  authentication=credentials,
  encryption=TLS,
  data=PaymentInfo
- **Shipping1ToNotify**:
  from=ShippingService_1,
  to=NotificationService,
  protocol=AMQP,
  port=5672,
  authentication=credentials,
  encryption=TLS,
  data=ShippingDetails
- **Shipping2ToNotify**:
  from=ShippingService_2,
  to=NotificationService,
  protocol=AMQP,
  port=5672,
  authentication=credentials,
  encryption=TLS,
  data=ShippingDetails

## Protocol Styles
- **AMQP**: color=darkorange, line_style=dashed

## Severity Multipliers
- **PaymentService_1**: 3.0
- **PaymentService_2**: 3.0
- **OrderQueue**: 2.0
- **NotificationService**: 1.0

## Custom Mitre Mapping
- **AMQP queue injection — poisoned order message**: {"tactics": ["Execution", "Impact"], "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}, {"id": "T1485", "name": "Data Destruction"}]}
- **Payment token interception via MITM on internal AMQP**: {"tactics": ["Collection", "Credential Access"], "techniques": [{"id": "T1557", "name": "Adversary-in-the-Middle"}, {"id": "T1528", "name": "Steal Application Access Token"}]}
