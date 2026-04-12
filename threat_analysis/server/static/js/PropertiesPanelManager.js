/*
 * Copyright 2025 ellipse2v
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// threat_analysis/server/static/js/PropertiesPanelManager.js
//
// Schema-driven properties panel — form fields are generated from DSL_SCHEMA
// (dsl_schema.js) so adding a field to the schema automatically surfaces it
// here. No hardcoded IDs, no duplicated option lists.

class PropertiesPanelManager {

    // Konva stereotype string → DSL_SCHEMA entity key
    static STEREOTYPE_TO_ENTITY = {
        BOUNDARY:    'boundary',
        ACTOR:       'actor',
        DATA:        'data',
        SERVER:      'server',
        WEB_SERVER:  'server',
        DATABASE:    'server',
        FIREWALL:    'server',
        ROUTER:      'server',
        SWITCH:      'server',
        API_GATEWAY: 'server',
    };

    // Keys handled as universal fixed fields (always rendered first)
    static UNIVERSAL_KEYS = new Set(['name', 'color']);

    // Dataflow fields managed by the graphical editor, absent from DSL_SCHEMA dataflow.fields
    static DATAFLOW_EXTRA_FIELDS = [
        { key: 'isEncrypted',     label: 'Is Encrypted',    type: 'checkbox' },
        { key: 'isAuthenticated', label: 'Is Authenticated', type: 'checkbox' },
        { key: 'line_style',      label: 'Line Style',       type: 'select',
          options: ['solid', 'dashed', 'dotted'] },
    ];

    constructor(layer, connectionManager) {
        this.layer             = layer;
        this.connectionManager = connectionManager;
        this.selectedItem      = null;

        this.propertiesForm = document.getElementById('properties-form');
        this.noSelectionDiv = document.getElementById('no-selection');

        window.addEventListener('itemSelected',    (e) => this.updatePropertiesPanel(e.detail.item));
        window.addEventListener('selectionCleared',()  => this.updatePropertiesPanel(null));
        window.addEventListener('nodeDeleted',     ()  => this.updatePropertiesPanel(null));
    }

    // ── Entity type resolution ────────────────────────────────────────────

    _entityType(item) {
        if (item instanceof Connection) return 'dataflow';
        const stereotype = item.getAttr('threatModelProperties')?.stereotype || '';
        return PropertiesPanelManager.STEREOTYPE_TO_ENTITY[stereotype] || 'server';
    }

    // ── Boolean coercion (DSL stores 'True'/'False' strings) ─────────────

    _toBool(v) {
        if (typeof v === 'boolean') return v;
        return v === 'True' || v === 'true' || v === 1;
    }

    // ── Effective field type resolution ───────────────────────────────────
    // Upgrades 'text' fields that have valueType:'select' in DSL_SCHEMA.attributes.
    // Degrades reference selects to plain text (graphical editor resolves via canvas).

    _effectiveType(field) {
        const type = field.type;
        if (type === 'boundary-select' || type === 'node-select') return 'text';
        if (type !== 'text') return type;

        const attr = (DSL_SCHEMA.attributes || []).find(a => a.key === field.key);
        if (!attr) return 'text';
        if (attr.valueType === 'select' && DSL_SCHEMA.values[field.key]) return 'select';
        return 'text';
    }

    // ── DOM helpers ───────────────────────────────────────────────────────

    _makeGroup(id) {
        const g = document.createElement('div');
        g.className = 'prop-group';
        if (id) g.id = id;
        return g;
    }

    _makeLabel(text, forId) {
        const l = document.createElement('label');
        l.textContent = text + ':';
        if (forId) l.htmlFor = forId;
        return l;
    }

    _makeSelect(id, options, currentValue) {
        const s = document.createElement('select');
        if (id) s.id = id;
        options.forEach(opt => {
            const o = document.createElement('option');
            o.value = opt;
            o.textContent = opt || '—';
            s.appendChild(o);
        });
        s.value = currentValue != null ? String(currentValue) : '';
        return s;
    }

    // ── Field builders ────────────────────────────────────────────────────

    // Build one form row from a DSL_SCHEMA field definition + current value.
    _buildSchemaField(field, value) {
        const inputId = `prop-schema-${field.key}`;
        const type    = this._effectiveType(field);
        const group   = this._makeGroup(`schema-field-${field.key}`);
        group.appendChild(this._makeLabel(field.label, inputId));

        let input;

        if (type === 'checkbox') {
            input = document.createElement('input');
            input.type    = 'checkbox';
            input.id      = inputId;
            input.checked = this._toBool(value);
            input.addEventListener('change', (e) =>
                this.updateCellProperty(field.key, e.target.checked));

        } else if (type === 'select') {
            const options = field.options || DSL_SCHEMA.values[field.key] || [];
            input = this._makeSelect(inputId, options, value != null ? value : (field.default_val || ''));
            input.addEventListener('change', (e) =>
                this.updateCellProperty(field.key, e.target.value));

        } else {
            input = document.createElement('input');
            input.type        = 'text';
            input.id          = inputId;
            input.placeholder = field.placeholder || '';
            input.value       = value != null ? String(value) : '';
            input.addEventListener('input', (e) =>
                this.updateCellProperty(field.key, e.target.value));
        }

        group.appendChild(input);
        return group;
    }

    // Name field — always first.
    _buildNameField(value) {
        const group = this._makeGroup();
        group.appendChild(this._makeLabel('Name', 'prop-name'));
        const input = document.createElement('input');
        input.type  = 'text';
        input.id    = 'prop-name';
        input.value = value || '';
        input.addEventListener('input', (e) => this.updateCellProperty('name', e.target.value));
        group.appendChild(input);
        return group;
    }

    // Color field — always second.
    _buildColorField(value) {
        const group = this._makeGroup();
        group.appendChild(this._makeLabel('Color', 'prop-color'));
        const input = document.createElement('input');
        input.type  = 'color';
        input.id    = 'prop-color';
        input.value = value || '#D1FAE5';
        input.addEventListener('input', (e) => this.updateCellProperty('color', e.target.value));
        group.appendChild(input);
        return group;
    }

    // Data select — populated from DATA nodes currently on the canvas.
    _buildDataSelect(currentValue) {
        const group = this._makeGroup('schema-field-data');
        group.appendChild(this._makeLabel('Data', 'prop-data'));
        const select = document.createElement('select');
        select.id = 'prop-data';
        const empty = document.createElement('option');
        empty.value = ''; empty.textContent = '—';
        select.appendChild(empty);
        this.layer.find('Group').forEach(n => {
            const p = n.getAttr('threatModelProperties');
            if (p && p.stereotype === 'DATA') {
                const o = document.createElement('option');
                o.value = p.name; o.textContent = p.name;
                select.appendChild(o);
            }
        });
        select.value = currentValue || '';
        select.addEventListener('change', (e) => this.updateCellProperty('data', e.target.value));
        group.appendChild(select);
        return group;
    }

    // CIA triad selects — graphical-editor specific, not in DSL_SCHEMA.
    _buildCIAGroup(props) {
        const group = this._makeGroup('prop-cia-group');
        group.appendChild(this._makeLabel('CIA'));
        const keys    = ['confidentiality', 'integrity', 'availability'];
        const prefixes = ['C', 'I', 'A'];
        keys.forEach((key, i) => {
            const p  = prefixes[i];
            const opts = ['low', 'medium', 'high', 'critical'].map(v => `${p}: ${v}`);
            const cur  = props[key] ? `${p}: ${props[key]}` : `${p}: medium`;
            const sel  = this._makeSelect(`prop-${key}`, opts, cur);
            sel.addEventListener('change', (e) =>
                this.updateCellProperty(key, e.target.value.split(': ')[1]));
            group.appendChild(sel);
        });
        return group;
    }

    // ── Form rendering ────────────────────────────────────────────────────

    _renderForm(entityType, props) {
        this.propertiesForm.innerHTML = '';

        // 1. Universal fields (always present)
        this.propertiesForm.appendChild(this._buildNameField(props.name));
        this.propertiesForm.appendChild(this._buildColorField(props.color));

        // 2. Schema-driven fields
        const entity = DSL_SCHEMA.entities[entityType];
        if (entity) {
            const skip = PropertiesPanelManager.UNIVERSAL_KEYS;
            // For dataflows, 'from' and 'to' are determined by the visual connection
            const dfSkip = new Set(['from', 'to']);
            entity.fields
                .filter(f => !skip.has(f.key) && !(entityType === 'dataflow' && dfSkip.has(f.key)))
                .forEach(f => this.propertiesForm.appendChild(
                    this._buildSchemaField(f, props[f.key])
                ));
        }

        // 3. Dataflow-only extras absent from DSL_SCHEMA dataflow.fields
        if (entityType === 'dataflow') {
            PropertiesPanelManager.DATAFLOW_EXTRA_FIELDS.forEach(f =>
                this.propertiesForm.appendChild(this._buildSchemaField(f, props[f.key]))
            );
            this.propertiesForm.appendChild(this._buildDataSelect(props.data));
        }

        // 4. CIA group for server / actor (graphical-editor specific scoring)
        if (entityType === 'server' || entityType === 'actor') {
            this.propertiesForm.appendChild(this._buildCIAGroup(props));
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    updatePropertiesPanel(item) {
        this.selectedItem = item;

        if (!item) {
            this.propertiesForm.style.display = 'none';
            this.noSelectionDiv.style.display  = 'block';
            return;
        }

        this.propertiesForm.style.display = 'block';
        this.noSelectionDiv.style.display  = 'none';

        const entityType = this._entityType(item);
        const props      = (item instanceof Connection)
            ? item.properties
            : (item.getAttr('threatModelProperties') || {});

        this._renderForm(entityType, props);
    }

    updateCellProperty(key, value) {
        if (!this.selectedItem) return;

        if (this.selectedItem instanceof Connection) {
            this.selectedItem.properties[key] = value;
            if (['name', 'data', 'isEncrypted', 'isAuthenticated'].includes(key)) {
                this.selectedItem.updateLabel();
            } else if (['color', 'line_style', 'protocol'].includes(key)) {
                this.selectedItem.updateStyle();
            }
            this.selectedItem.manager.layer.draw();

        } else if (this.selectedItem.getAttr('threatModelProperties')) {
            const node  = this.selectedItem;
            const props = node.getAttr('threatModelProperties');
            props[key]  = value;
            node.setAttr('threatModelProperties', props);

            if (key === 'name') {
                const textNode = node.findOne('.label');
                if (textNode) textNode.text(value);

            } else if (key === 'color') {
                const shape = node.findOne('.shape');
                if (shape) {
                    if (props.isFilled) shape.fill(value);
                    if (props.stereotype !== 'BOUNDARY') shape.stroke(value);
                }

            } else if (key === 'isTrusted') {
                const shape   = node.findOne('.shape');
                const trusted = this._toBool(value);
                props.isTrusted = trusted;
                if (shape && props.stereotype === 'BOUNDARY') {
                    shape.stroke(trusted ? '#adb5bd' : 'red');
                    shape.strokeWidth(trusted ? 2 : 1);
                }

            } else if (key === 'isFilled') {
                const shape  = node.findOne('.shape');
                const filled = this._toBool(value);
                if (shape) shape.fill(filled ? props.color : 'transparent');
            }

            this.layer.batchDraw();
        }
    }
}
