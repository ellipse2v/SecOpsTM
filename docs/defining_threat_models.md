# Defining Your Threat Model in Markdown

This guide provides a detailed explanation and examples for defining your threat models using the framework's Markdown-based Domain Specific Language (DSL). This approach allows for version control, automation, and collaborative threat modeling.

The structure of a Markdown threat model file is divided into several key sections, each defining different aspects of your system.

## Example Threat Model: Simple Monolithic Web Application

Let's walk through an example, similar to `threatModel_Template/Simple_Monolithic_Web_Application.md`, to illustrate each section.

````markdown
# Threat Model: Simple Monolithic Web Application

## Description
This threat model describes a simple monolithic web application, where all functionalities (user interface, business logic, data access) are grouped into a single codebase and deployed as a single unit. It examines typical vulnerabilities of this architecture, such as single points of failure, difficulty in isolating compromised components, and complexity in managing dependencies.

## Boundaries
- **Client (Web Browser)**: color=lightblue, isTrusted=False
- **Monolithic Web Server**: color=orange, isTrusted=False
- **Database**: color=purple, isTrusted=True

## Actors
- **End User**: boundary="Client (Web Browser)"
- **Administrator**: color=blue
- **Attacker**: color=red

## Servers
- **Load Balancer (Optional)**: color=lightgray, type="load_balancer"
- **Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)**: boundary="Monolithic Web Server", type="web_server"
- **Database Server (MySQL, PostgreSQL, MongoDB)**: boundary="Database", type="database"

## Dataflows
- **HTTP/S Request**: from="End User", to="Load Balancer (Optional)", protocol="HTTPS", color=darkgreen
- **Web Request**: from="Load Balancer (Optional)", to="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", protocol="HTTP/S", color=darkgreen
- **Database Request**: from="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", to="Database Server (MySQL, PostgreSQL, MongoDB)", protocol="JDBC/ODBC/API", color=purple, data=["User Credentials", "Application Data"]
- **Database Response**: from="Database Server (MySQL, PostgreSQL, MongoDB)", to="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", protocol="JDBC/ODBC/API", color=purple, data=["User Credentials", "Application Data"]
- **Web Response**: from="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", to="Load Balancer (Optional)", protocol="HTTP/S", color=darkgreen
- **HTTP/S Response**: from="Load Balancer (Optional)", to="End User", protocol="HTTPS", color=darkgreen
- **Code Injection**: from="Attacker", to="Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)", protocol="HTTP/S", color=red
- **Direct Database Access**: from="Attacker", to="Database Server (MySQL, PostgreSQL, MongoDB)", protocol="SQL/NoSQL", color=purple

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **SSH**: color=blue, line_style=dashed
- **SQL**: color=purple
- **LDAPS**: color=teal
- **MQTT**: color=teal, line_style=dashed
- **JDBC/ODBC/API**: color=purple
- **SQL/NoSQL**: color=purple

## Data Objects
- **User Credentials**: classification=Secret
- **Application Data**: classification=Sensitive

## Severity Multipliers
- **Monolithic Application (e.g., PHP, Ruby on Rails, Node.js Express)**: 1.8 (single point of failure, broad impact on compromise)
- **Database Server (MySQL, PostgreSQL, MongoDB)**: 1.9 (contains all application data)

## Custom Mitre Mapping
- **Path Traversal**: tactics=["Impact"], techniques=[{"id": "T1083", "name": "File and Directory Discovery"}]
- **Insecure Direct Object Reference (IDOR)**: tactics=["Impact"], techniques=[{"id": "T1530", "name": "Data from Local System"}]

````

## Section Breakdown

### Threat Model Title (`# Threat Model: ...`)

The first line of your Markdown file should define the title of your threat model using a single hash (`#`). This title will be used in reports and diagrams.

### Description (`## Description`)

Following the title, a `## Description` section provides a high-level overview of the system being modeled. This is free-form text that helps contextualize the threat model.

### Boundaries (`## Boundaries`)

Boundaries represent trust zones or logical separations within your system. They are crucial for identifying threats that occur when data crosses trust levels.

-   Each boundary is defined by a hyphen (`-`), followed by its **name**.
-   **`color` (optional)**: Assigns a color for visualization in diagrams. You can use standard CSS color names (e.g., `lightblue`, `orange`) or hexadecimal codes.
-   **`isTrusted` (optional, default: `True`)**: A boolean flag indicating whether the boundary is considered trusted. This is used by the rule-based threat engine to identify threats related to trust boundary violations.

    ```markdown
    ## Boundaries
    - **Client (Web Browser)**: color=lightblue, isTrusted=False
    - **Internal Network**: color=green, isTrusted=True
    ```

### Actors (`## Actors`)

Actors represent entities that interact with your system, both human and automated.

-   Each actor is defined by a hyphen (`-`), followed by its **name**.
-   **`boundary` (optional)**: Specifies which boundary the actor resides within. If omitted, the actor is considered external to any explicit boundary.
-   **`color` (optional)**: Assigns a color for visualization.

    ```markdown
    ## Actors
    - **End User**: boundary="Client (Web Browser)"
    - **Administrator**: color=blue
    ```

### Servers (`## Servers`)

Servers represent computational resources or applications within your system. These can be physical servers, virtual machines, containers, microservices, or external services.

-   Each server is defined by a hyphen (`-`), followed by its **name**.
-   **`boundary` (optional)**: Specifies which boundary the server resides within.
-   **`type` (optional)**: This is crucial for visual representation and can influence custom threat rules. The framework uses this type to select an appropriate icon for the server in generated diagrams.
    -   **Available `type` values (and their corresponding icons/shapes):**
        -   `actor` (circle)
        -   `web_server` (rectangle, web icon)
        -   `database` (cylinder, database icon)
        -   `firewall` (hexagon, firewall icon)
        -   `router` (diamond, router icon)
        -   `switch` (diamond, switch icon)
        -   `load_balancer` (rectangle, load balancer icon)
        -   `api_gateway` (rectangle, API gateway icon)
        -   `app_server` (rectangle, application server icon)
        -   `central_server` (rectangle, central server icon)
        -   `authentication_server` (rectangle, authentication icon)
        -   `server` (default rectangle, generic server icon if no specific type matches)
    -   If an `svg` icon is not found for a given type, the system falls back to a text-based Unicode character icon.
-   **`color` (optional)**: Assigns a color for visualization.

    ```markdown
    ## Servers
    - **Load Balancer**: type="load_balancer"
    - **Web Application**: boundary="Monolithic Web Server", type="web_server"
    - **PostgreSQL DB**: boundary="Database", type="database"
    ```

### Dataflows (`## Dataflows`)

Dataflows describe the communication paths and data transfers between actors and servers.

-   Each dataflow is defined by a hyphen (`-`), followed by its **name**.
-   **`from`**: The source of the dataflow (an actor or a server).
-   **`to`**: The destination of the dataflow (an actor or a server).
-   **`protocol` (optional)**: The protocol used for the data transfer (e.g., `HTTPS`, `HTTP`, `SQL`, `SSH`). This is used for both visual styling and by threat rules.
-   **`color` (optional)**: Assigns a color for visualization.
-   **`data` (optional)**: A list of `Data Objects` (defined in the `## Data Objects` section) that are transferred over this dataflow. This is critical for identifying information disclosure or tampering threats.

    ```markdown
    ## Dataflows
    - **User Login**: from="End User", to="Web Application", protocol="HTTPS", data=["User Credentials"]
    - **API Call**: from="Web Application", to="Backend Service", protocol="HTTP", color=orange
    ```

### Protocol Styles (`## Protocol Styles`)

This section allows you to define custom visual styles for different protocols in your diagrams.

-   Each protocol style is defined by a hyphen (`-`), followed by the **protocol name**.
-   **`color` (optional)**: Assigns a color to the dataflow line.
-   **`line_style` (optional)**: Defines the style of the line. Options include `solid`, `dashed`, `dotted`.

    ```markdown
    ## Protocol Styles
    - **HTTPS**: color=darkgreen, line_style=solid
    - **HTTP**: color=red, line_style=dashed
    ```

### Data Objects (`## Data Objects`)

Data Objects represent sensitive data elements that are processed, stored, or transmitted within your system. Defining these allows the framework to identify threats like information disclosure or tampering.

-   Each data object is defined by a hyphen (`-`), followed by its **name**.
-   **`classification` (optional, default: `Public`)**: The sensitivity level of the data.
    -   **Available `classification` values:** `Public`, `Internal`, `Sensitive`, `Secret`, `Top Secret`.
    -   This classification is used by threat rules to identify threats related to sensitive data handling, especially when crossing trust boundaries or being transmitted insecurely.

    ```markdown
    ## Data Objects
    - **User Credentials**: classification=Secret
    - **Application Logs**: classification=Internal
    ```

### Severity Multipliers (`## Severity Multipliers`)

This section allows you to fine-tune the calculated severity of threats for specific components. If a threat is identified against a component listed here, its severity score will be multiplied by the specified factor.

-   Each entry is defined by a hyphen (`-`), followed by the **name of the component** (actor or server).
-   The value after the colon (`:`) is the **multiplier**.

    ```markdown
    ## Severity Multipliers
    - **Database Server**: 1.5 (due to critical data stored)
    - **Admin Interface**: 2.0 (high impact on compromise)
    ```

### Custom Mitre Mapping (`## Custom Mitre Mapping`)

This section allows you to directly map custom threats or specific attack patterns to MITRE ATT&CK tactics and techniques, which will be included in the generated ATT&CK Navigator layers and reports.

-   Each entry is defined by a hyphen (`-`), followed by the **name of your custom threat** or attack pattern.
-   **`tactics`**: A list of MITRE ATT&CK tactics that this threat relates to (e.g., `["Impact", "Defense Evasion"]`).
-   **`techniques`**: A list of MITRE ATT&CK techniques. Each technique should be an object with an `id` (e.g., `"T1083"`) and a `name` (e.g., `"File and Directory Discovery"`).

    ```markdown
    ## Custom Mitre Mapping
    - **SQL Injection**: tactics=["Execution", "Defense Evasion"], techniques=[{"id": "T1190", "name": "Exploit Public-Facing Application"}]
    ```

## Adding Custom Rule-Based Threats

The framework provides a powerful rule-based engine for defining custom threats that go beyond the standard PyTM threat generation. These rules are defined in Python within `threat_analysis/threat_rules.py` and evaluated by `threat_analysis/custom_threats.py`.

To add a new custom threat:

1.  **Open `threat_analysis/threat_rules.py`**.
2.  **Locate the `THREAT_RULES` dictionary**. This dictionary is structured by component type (`servers`, `dataflows`, `actors`).
3.  **Add a new rule** under the appropriate component type. Each rule consists of:
    -   `"conditions"`: A dictionary of key-value pairs that describe the properties a component must have for the threat to apply. You can use dot notation for nested properties (e.g., `source.inBoundary.isTrusted`).
    -   `"threats"`: A list of threat templates to generate if the conditions are met. Each template requires a `description`, `stride_category`, `impact` (1-5), `likelihood` (1-5), and optionally `capec_ids` (a list of CAPEC IDs) or `mitigations`.

### Understanding Conditions and Available Properties

The `conditions` in `THREAT_RULES` are highly flexible. You can access properties of the component itself, or for dataflows, properties of its `source` and `sink` and their respective `inBoundary` objects.

**Commonly Used Properties in Conditions:**

-   **For `servers` and `actors`:**
    -   `name`: The name of the server/actor.
    -   `type`: The type of the server (e.g., `web_server`, `database`).
    -   `boundary.isTrusted`: Whether the boundary the component is in is trusted.
    -   `boundary.name`: The name of the boundary the component is in.
-   **For `dataflows`:**
    -   `name`: The name of the dataflow.
    -   `protocol`: The protocol of the dataflow (e.g., `HTTP`, `HTTPS`).
    -   `is_encrypted`: (Boolean) Whether the dataflow is explicitly marked as encrypted.
    -   `source.name`, `sink.name`: The names of the source and sink components.
    -   `source.inBoundary.isTrusted`, `sink.inBoundary.isTrusted`: Whether the source/sink boundaries are trusted.
    -   `crosses_trust_boundary`: (Special computed condition) `True` if the dataflow crosses from a trusted to an untrusted boundary, or vice-versa.
    -   `contains_sensitive_data`: (Special computed condition) `True` if any `Data Objects` flowing through it have a `classification` of `Sensitive`, `Secret`, or `Top Secret`.

### Example Custom Rule (in `threat_analysis/threat_rules.py`)

```python
THREAT_RULES = {
    "servers": [
        # ... other server rules
        {
            "conditions": {
                "type": "database",
                "boundary.isTrusted": False # An untrusted boundary
            },
            "threats": [
                {
                    "description": "Untrusted database connection for {name}. Potential for unauthorized access.",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 4,
                    "capec_ids": ["CAPEC-11", "CAPEC-12"]
                }
            ]
        }
    ],
    "dataflows": [
        # ... other dataflow rules
        {
            "conditions": {
                "protocol": "HTTP",
                "contains_sensitive_data": True,
                "crosses_trust_boundary": True
            },
            "threats": [
                {
                    "description": "Sensitive data transmitted over unencrypted HTTP across trust boundary from {source.name} to {sink.name}. High risk of eavesdropping.",
                    "stride_category": "Information Disclosure",
                    "impact": 5,
                    "likelihood": 5,
                    "capec_ids": ["CAPEC-98", "CAPEC-592"]
                }
            ]
        }
    ],
    "actors": [
        # ... other actor rules
    ]
}
```

By leveraging this rule-based system, you can precisely define security policies and automatically generate threats based on the specific architectural patterns and data handling practices in your threat model.