# Naming Conventions

## Overview

Proper naming conventions ensure consistency and readability in system models.

## Asset Names

**Format:** `snake_case`

**Rules:**
- Use lowercase letters and underscores
- Be descriptive but concise
- Avoid abbreviations unless well-known

**Examples:**
- ✅ `api_gateway`
- ✅ `web_server`
- ✅ `database_primary`
- ❌ `APIGateway` (camelCase)
- ❌ `api-gateway` (kebab-case)
- ❌ `API Gateway` (spaces)

## Protocol Names

**Format:** `kebab-case` (with version when applicable)

**Rules:**
- Use lowercase letters and hyphens
- Include version numbers for specific protocols
- Use standard protocol names where possible

**Examples:**
- ✅ `https`
- ✅ `ocusync-3-enterprise`
- ✅ `mqtt-5`
- ❌ `HTTPS` (uppercase)
- ❌ `ocousync_3_enterprise` (snake_case)

## File Names

**Format:** `snake_case.yaml` or `snake_case.md`

**Rules:**
- Use lowercase letters and underscores
- Use appropriate extension (`.yaml`, `.md`)

**Examples:**
- ✅ `api_gateway.yaml`
- ✅ `context-format.md`
- ❌ `ApiGateway.yaml`
- ❌ `api-gateway.yaml`

## Subsystem Names

**Format:** `snake_case` + `_subsystem` suffix

**Rules:**
- Describe the subsystem's function or domain
- Add `_subsystem` suffix for clarity

**Examples:**
- ✅ `drone_subsystem`
- ✅ `ground_subsystem`
- ✅ `cloud_subsystem`
- ❌ `Drone` (too vague)
- ❌ `drone-system` (wrong format)

## Boundary Names

**Format:** Descriptive name (can use kebab-case or snake_case)

**Rules:**
- Clearly describe the trust boundary
- Be consistent within the same model

**Examples:**
- ✅ `internet`
- ✅ `dmz`
- ✅ `internal_network`
- ✅ `cloud-provider`

## Server/Component Names

**Format:** `snake_case`

**Rules:**
- Describe the component's function
- Include role when multiple instances exist

**Examples:**
- ✅ `auth_server`
- ✅ `database_primary`
- ✅ `database_replica`
- ✅ `web_server_frontend`

## Data Names

**Format:** `snake_case`

**Rules:**
- Describe the data type or content
- Be specific about sensitivity when relevant

**Examples:**
- ✅ `user_credentials`
- ✅ `session_token`
- ✅ `customer_pii`
- ✅ `encryption_key`

## Best Practices

1. **Consistency:** Use the same naming pattern throughout the model
2. **Clarity:** Names should be self-explanatory
3. **Avoid Ambiguity:** Don't use generic names like `server1`, `server2`
4. **Document Exceptions:** If you must break conventions, document why
5. **Review:** Check naming consistency during validation

## Common Mistakes

| ❌ Wrong | ✅ Correct | Reason |
|----------|-----------|--------|
| `API-Gateway` | `api_gateway` | Use snake_case for assets |
| `WebServer` | `web_server` | Use snake_case, not camelCase |
| `database1` | `database_primary` | Be descriptive |
| `HTTPS` | `https` | Protocol names in lowercase |
| `User Data` | `user_data` | No spaces in names |

## Related Documents

- [dsl-syntax.md](dsl-syntax.md) - DSL syntax specification
- [bom-format.md](bom-format.md) - BOM file format
- [context-format.md](context-format.md) - Context file format
- [workflow.md](workflow.md) - Threat modeling workflow
