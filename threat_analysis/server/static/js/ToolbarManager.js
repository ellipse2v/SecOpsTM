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
// threat_analysis/server/static/js/ToolbarManager.js

class ToolbarManager {
    constructor(nodeManager, transformer, propertiesPanelManager) {
        this.nodeManager = nodeManager;
        this.transformer = transformer;
        this.propertiesPanelManager = propertiesPanelManager;
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        document.getElementById('add-boundary').addEventListener('click', () => {
            const group = this.nodeManager.addNode('BOUNDARY', this.nodeManager.findUniqueName('New Boundary'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-actor').addEventListener('click', () => {
            const group = this.nodeManager.addNode('ACTOR', this.nodeManager.findUniqueName('New Actor'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-server').addEventListener('click', () => {
            const group = this.nodeManager.addNode('SERVER', this.nodeManager.findUniqueName('New Server'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-web-server').addEventListener('click', () => {
            const group = this.nodeManager.addNode('WEB_SERVER', this.nodeManager.findUniqueName('Web Server'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-database').addEventListener('click', () => {
            const group = this.nodeManager.addNode('DATABASE', this.nodeManager.findUniqueName('Database'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-firewall').addEventListener('click', () => {
            const group = this.nodeManager.addNode('FIREWALL', this.nodeManager.findUniqueName('Firewall'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-router').addEventListener('click', () => {
            const group = this.nodeManager.addNode('ROUTER', this.nodeManager.findUniqueName('Router'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-switch').addEventListener('click', () => {
            const group = this.nodeManager.addNode('SWITCH', this.nodeManager.findUniqueName('New Switch'), 50, 50);
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-data').addEventListener('click', () => {
            window.modelManager.openDataManager();
        });
    }
}