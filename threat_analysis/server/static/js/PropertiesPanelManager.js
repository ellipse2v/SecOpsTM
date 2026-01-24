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

class PropertiesPanelManager {

    constructor(layer, connectionManager) {

        this.layer = layer;

        this.connectionManager = connectionManager;

        this.selectedItem = null; // Track the currently selected item (node or connection)

        this.propertiesForm = document.getElementById('properties-form');

        this.noSelectionDiv = document.getElementById('no-selection');

        this.nameInput = document.getElementById('prop-name');

        this.colorInput = document.getElementById('prop-color');

        this.descriptionInput = document.getElementById('prop-description');

        this.osInput = document.getElementById('prop-os');

        this.stereotypeInput = document.getElementById('prop-stereotype');

        this.isFilledInput = document.getElementById('prop-is-filled');

        this.isTrustedInput = document.getElementById('prop-is-trusted');

        this.lineStyleInput = document.getElementById('prop-line-style');

        this.formatInput = document.getElementById('prop-format');

        this.credentialsLifeInput = document.getElementById('prop-credentials-life');

        this.classificationInput = document.getElementById('prop-classification');

        this.confidentialityInput = document.getElementById('prop-confidentiality');

        this.integrityInput = document.getElementById('prop-integrity');

        this.availabilityInput = document.getElementById('prop-availability');

        this.protocolInput = document.getElementById('prop-protocol');

        this.isEncryptedInput = document.getElementById('prop-is-encrypted');

        this.isAuthenticatedInput = document.getElementById('prop-is-authenticated');

        this.dataInput = document.getElementById('prop-data');

        

        this.setupEventHandlers();

    }



    setupEventHandlers() {

        this.nameInput.addEventListener('input', (evt) => this.updateCellProperty('name', evt.target.value));

        this.colorInput.addEventListener('input', (evt) => this.updateCellProperty('color', evt.target.value));

        this.descriptionInput.addEventListener('input', (evt) => this.updateCellProperty('description', evt.target.value));

        this.osInput.addEventListener('input', (evt) => this.updateCellProperty('os', evt.target.value));

        this.stereotypeInput.addEventListener('input', (evt) => this.updateCellProperty('stereotype', evt.target.value));

        this.isFilledInput.addEventListener('change', (evt) => this.updateCellProperty('isFilled', evt.target.checked));

        this.isTrustedInput.addEventListener('change', (evt) => this.updateCellProperty('isTrusted', evt.target.checked));

        this.lineStyleInput.addEventListener('change', (evt) => this.updateCellProperty('line_style', evt.target.value));

        this.formatInput.addEventListener('input', (evt) => this.updateCellProperty('format', evt.target.value));

        this.credentialsLifeInput.addEventListener('input', (evt) => this.updateCellProperty('credentialsLife', evt.target.value));

        this.classificationInput.addEventListener('change', (evt) => this.updateCellProperty('classification', evt.target.value));

        this.confidentialityInput.addEventListener('change', (evt) => this.updateCellProperty('confidentiality', evt.target.value));

        this.integrityInput.addEventListener('change', (evt) => this.updateCellProperty('integrity', evt.target.value));

        this.availabilityInput.addEventListener('change', (evt) => this.updateCellProperty('availability', evt.target.value));

        this.protocolInput.addEventListener('change', (evt) => this.updateCellProperty('protocol', evt.target.value));

        this.isEncryptedInput.addEventListener('change', (evt) => this.updateCellProperty('isEncrypted', evt.target.checked));

        this.isAuthenticatedInput.addEventListener('change', (evt) => this.updateCellProperty('isAuthenticated', evt.target.checked));

        this.dataInput.addEventListener('input', (evt) => this.updateCellProperty('data', evt.target.value));



        window.addEventListener('itemSelected', (e) => this.updatePropertiesPanel(e.detail.item));

        window.addEventListener('selectionCleared', () => this.updatePropertiesPanel(null));

        window.addEventListener('nodeDeleted', () => this.updatePropertiesPanel(null)); // Clear panel on node deletion

    }



    updatePropertiesPanel(item) {

        this.selectedItem = item; // Store the selected item

        if (item instanceof Connection) {

            const props = item.properties;

            this.propertiesForm.style.display = 'block';

            this.noSelectionDiv.style.display = 'none';



            this.nameInput.value = props.name;

            this.descriptionInput.value = props.description;

            this.protocolInput.value = props.protocol;

            this.isEncryptedInput.checked = props.isEncrypted;

            this.isAuthenticatedInput.checked = props.isAuthenticated;

            this.colorInput.value = props.color || '#000000';

            this.dataInput.value = props.data || '';
            // If the value doesn't exist in the dropdown, add it as a temporary option
            if (props.data && !Array.from(this.dataInput.options).some(opt => opt.value === props.data)) {
                const opt = document.createElement('option');
                opt.value = props.data;
                opt.textContent = props.data;
                this.dataInput.appendChild(opt);
                this.dataInput.value = props.data;
            }

            this.lineStyleInput.value = props.line_style || 'solid';



            document.getElementById('prop-os-group').style.display = 'none';

            document.getElementById('prop-stereotype-group').style.display = 'none';

            document.getElementById('prop-is-filled-group').style.display = 'none';

            document.getElementById('prop-is-trusted-group').style.display = 'none';

            document.getElementById('prop-line-style-group').style.display = 'block';

            document.getElementById('prop-format-group').style.display = 'none';

            document.getElementById('prop-credentials-life-group').style.display = 'none';

            document.getElementById('prop-classification-group').style.display = 'none';

            document.getElementById('prop-cia-group').style.display = 'none';



            this.colorInput.parentElement.style.display = 'block';

            document.getElementById('prop-protocol-group').style.display = 'block';

            document.getElementById('prop-is-encrypted-group').style.display = 'block';

            document.getElementById('prop-is-authenticated-group').style.display = 'block';

            document.getElementById('prop-description-group').style.display = 'block';

            document.getElementById('prop-data-group').style.display = 'block';



        } else if (item && item.getAttr('threatModelProperties')) {

            const props = item.getAttr('threatModelProperties');

            this.propertiesForm.style.display = 'block';

            this.noSelectionDiv.style.display = 'none';



            const type = props.stereotype;

            this.nameInput.value = props.name || '';

            this.descriptionInput.value = props.description || '';

            this.osInput.value = props.os || '';

            this.stereotypeInput.value = props.stereotype || '';

            this.isFilledInput.checked = props.isFilled !== undefined ? props.isFilled : true;

            this.isTrustedInput.checked = props.isTrusted !== undefined ? props.isTrusted : true;

            this.lineStyleInput.value = props.lineStyle || 'solid';

            this.formatInput.value = props.format || '';

            this.credentialsLifeInput.value = props.credentialsLife || '';

            this.classificationInput.value = props.classification || 'public';

            this.confidentialityInput.value = props.confidentiality || 'medium';

            this.integrityInput.value = props.integrity || 'medium';

            this.availabilityInput.value = props.availability || 'medium';

            this.colorInput.value = props.color || '#D1FAE5';



            const isData = (type === 'DATA');

            const isBoundary = (type === 'BOUNDARY');

            const isServer = (type === 'SERVER' || type === 'WEB_SERVER' || type === 'DATABASE' || type === 'FIREWALL' || type === 'ROUTER' || type === 'SWITCH' || type === 'API_GATEWAY');

            document.getElementById('prop-protocol-group').style.display = 'none';

            document.getElementById('prop-is-encrypted-group').style.display = 'none';

            document.getElementById('prop-is-authenticated-group').style.display = 'none';

            document.getElementById('prop-data-group').style.display = 'none';

            document.getElementById('prop-classification-group').style.display = isData ? 'block' : 'none';

            document.getElementById('prop-os-group').style.display = isServer ? 'block' : 'none';

            document.getElementById('prop-stereotype-group').style.display = isServer ? 'block' : 'none';

            document.getElementById('prop-is-filled-group').style.display = isBoundary || type === 'ACTOR' ? 'block' : 'none';

            document.getElementById('prop-is-trusted-group').style.display = isBoundary ? 'block' : 'none';

            document.getElementById('prop-line-style-group').style.display = isBoundary ? 'block' : 'none';

            document.getElementById('prop-format-group').style.display = isData ? 'block' : 'none';

            document.getElementById('prop-credentials-life-group').style.display = isData ? 'block' : 'none';

            this.colorInput.parentElement.style.display = 'block';

            document.getElementById('prop-cia-group').style.display = 'block';



        } else {

            this.propertiesForm.style.display = 'none';

            this.noSelectionDiv.style.display = 'block';

        }

    }



    updateCellProperty(key, value) {

        if (!this.selectedItem) return;



        if (this.selectedItem instanceof Connection) {
            this.selectedItem.properties[key] = value;

            if (key === "name" || key === "data" || key === "isEncrypted" || key === "isAuthenticated") {
                this.selectedItem.updateLabel();
            } else if (key === "color" || key === "line_style" || key === "protocol") {
                this.selectedItem.updateStyle();
                if (key === "protocol" || key === "color") {
                    this.connectionManager.updateAllConnectionsWithProtocol(this.selectedItem.properties.protocol);
                }
            }
            this.selectedItem.manager.layer.draw();

        } else if (this.selectedItem.getAttr('threatModelProperties')) {

            const node = this.selectedItem;

            const props = node.getAttr('threatModelProperties');

            props[key] = value;

            node.setAttr('threatModelProperties', props);



            if (key === 'name') {

                const textNode = node.findOne('.label');

                if (textNode) {

                    textNode.text(value);

                }

            } else if (key === 'color') {

                const shapeNode = node.findOne('.shape');

                if (shapeNode) {

                    props.color = value;

                    if (props.isFilled) {

                        shapeNode.fill(value);

                    }

                    if (props.stereotype !== 'BOUNDARY') {

                        shapeNode.stroke(value);

                    }

                }

            } else if (key === 'isTrusted') {

                const shapeNode = node.findOne('.shape');

                if (shapeNode && props.stereotype === 'BOUNDARY') {

                    shapeNode.stroke(value ? '#adb5bd' : 'red');

                    shapeNode.strokeWidth(value ? 2 : 1);

                }

            } else if (key === 'isFilled') {

                const shapeNode = node.findOne('.shape');

                if (shapeNode) {

                    shapeNode.fill(value ? props.color : 'transparent');

                }

            } else if (key === 'lineStyle') {

                const shapeNode = node.findOne('.shape');

                if (shapeNode) {

                    if (value === 'dashed') {

                        shapeNode.dash([10, 5]);

                    }

                    else if (value === 'dotted') {

                        shapeNode.dash([2, 5]);

                    }

                    else {

                        shapeNode.dash([]);

                    }

                }

            }

            this.layer.batchDraw();

        }

    }

}