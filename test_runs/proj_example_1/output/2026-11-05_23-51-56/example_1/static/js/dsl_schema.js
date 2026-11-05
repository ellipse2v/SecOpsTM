// Copyright 2025 ellipse2v
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * DSL_SCHEMA — single source of truth for the SecOpsTM Markdown DSL.
 *
 * Used by:
 *   - ComponentPanel  (simple_mode.html) — dynamically generates entity forms
 *   - attachDslAutocomplete              — derives SECTIONS / ATTRIBUTES / VALUES
 *
 * To add a new entity field: add one entry to the relevant `entities[x].fields`
 * array.  The panel and autocomplete pick it up automatically — no other changes
 * needed.
 *
 * Field types
 * -----------
 * - text           : <input type="text">
 * - select         : <select> with `options` array
 * - checkbox       : <input type="checkbox"> — writes 'True' when checked
 * - boundary-select: <select> populated live from ## Boundaries names
 * - node-select    : <select> populated live from ## Actors + ## Servers names
 *
 * Attribute valueTypes (for autocomplete)
 * ----------------------------------------
 * - bool         : suggests ['True', 'False']
 * - select       : suggests DSL_SCHEMA.values[attr.key]
 * - boundary-ref : suggests boundary names from editor content
 * - node-ref     : suggests actor + server names from editor content
 * - text         : no value suggestions
 */
window.DSL_SCHEMA = {

  // ── Section headers recognised by ModelParser ───────────────────────────
  sections: [
    '## Description',
    '## Context',
    '## Boundaries',
    '## Actors',
    '## Servers',
    '## Data',
    '## Dataflows',
    '## Protocol Styles',
    '## Severity Multipliers',
    '## Custom Mitre Mapping',
  ],

  // ── Entity definitions (drive Component Panel forms) ────────────────────
  entities: {
    boundary: {
      section: '## Boundaries',
      label:   'Boundary',
      fields: [
        { key: 'name',                 label: 'Name',                 type: 'text',     placeholder: 'e.g., Internet',     required: true },
        { key: 'color',                label: 'Color',                type: 'text',     placeholder: 'lightcoral' },
        { key: 'isTrusted',            label: 'Trusted',              type: 'select',   options: ['True', 'False'],         default_val: 'True' },
        { key: 'traversal_difficulty', label: 'Traversal difficulty', type: 'select',   options: ['', 'low', 'medium', 'high'] },
      ],
    },

    actor: {
      section: '## Actors',
      label:   'Actor',
      fields: [
        { key: 'name',        label: 'Name',        type: 'text',            placeholder: 'e.g., End User',      required: true },
        { key: 'boundary',    label: 'Boundary',    type: 'boundary-select' },
        { key: 'description', label: 'Description', type: 'text',            placeholder: 'Short description' },
        { key: 'color',       label: 'Color',       type: 'text',            placeholder: 'e.g., blue' },
        { key: 'isFilled',    label: 'isFilled',    type: 'checkbox', default_checked: true },
      ],
    },

    server: {
      section: '## Servers',
      label:   'Server',
      fields: [
        { key: 'name',               label: 'Name',               type: 'text',   placeholder: 'e.g., Backend API', required: true },
        { key: 'boundary',           label: 'Boundary',           type: 'boundary-select' },
        { key: 'type',               label: 'Type',               type: 'select',
          options: [
            '', 'web_server', 'api_server', 'database', 'cache', 'load_balancer',
            'microservice', 'faas', 'message_broker', 'message_queue', 'cdn',
            'api_gateway', 'waf', 'secrets_manager', 'iam', 'identity_provider',
            'monitoring', 'object_storage', 'registry', 'workstation', 'router',
            'switch', 'proxy', 'firewall', 'ids_ips', 'vpn_gateway',
            'domain_controller', 'container', 'lambda', 'storage',
            'file_server', 'dns_server', 'mail_server',
          ],
        },
        { key: 'description',        label: 'Description',        type: 'text',   placeholder: 'Short description' },
        { key: 'internet_facing',    label: 'internet_facing',    type: 'checkbox' },
        { key: 'credentials_stored', label: 'credentials_stored', type: 'checkbox' },
      ],
    },

    dataflow: {
      section: '## Dataflows',
      label:   'Dataflow',
      fields: [
        { key: 'name',          label: 'Name',          type: 'text',        placeholder: 'e.g., API to DB',  required: true },
        { key: 'from',          label: 'From',          type: 'node-select' },
        { key: 'to',            label: 'To',            type: 'node-select' },
        { key: 'protocol',      label: 'Protocol',      type: 'text',        placeholder: 'e.g., HTTPS' },
        { key: 'color',         label: 'Color',         type: 'text',        placeholder: 'e.g., darkgreen' },
        { key: 'bidirectional', label: 'bidirectional', type: 'checkbox' },
      ],
    },

    data: {
      section: '## Data',
      label:   'Data',
      fields: [
        { key: 'name',            label: 'Name',             type: 'text',   placeholder: 'e.g., User PII',  required: true },
        { key: 'classification',  label: 'Classification',   type: 'select',
          options: ['', 'PUBLIC', 'RESTRICTED', 'INTERNAL', 'SENSITIVE', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
        },
        { key: 'credentialsLife', label: 'Credentials life', type: 'select',
          options: ['', 'NONE', 'SHORT', 'SHORTLIVED', 'LONG', 'UNKNOWN'],
        },
        { key: 'description',     label: 'Description',      type: 'text',   placeholder: 'Short description' },
      ],
    },
  },

  // ── Attribute metadata (drive autocomplete suggestions) ─────────────────
  attributes: [
    { key: 'boundary',              detail: 'assign to boundary zone',          valueType: 'boundary-ref' },
    { key: 'type',                  detail: 'component type',                   valueType: 'select' },
    { key: 'isTrusted',             detail: 'trust level (True/False)',          valueType: 'bool' },
    { key: 'isAdmin',               detail: 'admin component (True/False)',      valueType: 'bool' },
    { key: 'isPublic',              detail: 'public-facing (True/False)',        valueType: 'bool' },
    { key: 'internet_facing',       detail: 'internet-exposed (True/False)',     valueType: 'bool' },
    { key: 'credentials_stored',    detail: 'stores credentials (True/False)',   valueType: 'bool' },
    { key: 'submodel',              detail: 'path to sub-model file',           valueType: 'text' },
    { key: 'authenticity',          detail: 'authentication strength',           valueType: 'select' },
    { key: 'from',                  detail: 'dataflow source',                  valueType: 'node-ref' },
    { key: 'to',                    detail: 'dataflow target',                  valueType: 'node-ref' },
    { key: 'protocol',              detail: 'communication protocol',           valueType: 'select' },
    { key: 'isEncrypted',           detail: 'encrypted transport (True/False)',  valueType: 'bool' },
    { key: 'isAuthenticated',       detail: 'requires auth (True/False)',        valueType: 'bool' },
    { key: 'sanitizesInput',        detail: 'input validation (True/False)',     valueType: 'bool' },
    { key: 'bidirectional',         detail: 'bidirectional flow (True/False)',   valueType: 'bool' },
    { key: 'classification',        detail: 'data sensitivity level',           valueType: 'select' },
    { key: 'lifetime',              detail: 'data retention lifetime',          valueType: 'select' },
    { key: 'traversal_difficulty',  detail: 'boundary crossing difficulty',     valueType: 'select' },
  ],

  // ── Valid values for select / bool attributes ───────────────────────────
  values: {
    bool: ['True', 'False'],

    type: [
      'web_server', 'api_server', 'database', 'cache', 'load_balancer', 'microservice',
      'faas', 'message_broker', 'message_queue', 'cdn', 'api_gateway', 'waf',
      'secrets_manager', 'iam', 'identity_provider', 'monitoring', 'object_storage',
      'registry', 'workstation', 'router', 'switch', 'proxy', 'firewall', 'ids_ips',
      'vpn_gateway', 'domain_controller', 'container', 'lambda', 'storage',
      'file_server', 'dns_server', 'mail_server',
    ],

    authenticity: ['none', 'credentials', 'two-factor', 'sso', 'certificate'],

    protocol: [
      'HTTP', 'HTTPS', 'TLS', 'SSH', 'SFTP', 'FTP', 'FTPS',
      'SQL', 'TCP', 'UDP', 'gRPC', 'AMQP', 'MQTT', 'WebSocket',
      'REST', 'SOAP', 'GraphQL', 'LDAP', 'LDAPS', 'Kerberos',
      'RDP', 'VPN', 'ICMP', 'DNS', 'SMB', 'NFS',
    ],

    classification:       ['PUBLIC', 'RESTRICTED', 'INTERNAL', 'SENSITIVE', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'],
    lifetime:             ['NONE', 'SHORT', 'LONG', 'AUTO', 'PERMANENT'],
    traversal_difficulty: ['low', 'medium', 'high'],
  },
};
