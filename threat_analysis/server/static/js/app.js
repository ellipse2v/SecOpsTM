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
// threat_analysis/server/static/js/App.js

document.addEventListener('DOMContentLoaded', () => {
    const konvaManager = new KonvaManager('graph-container');
    const nodeManager = new NodeManager(konvaManager.getLayer(), konvaManager.getTransformer());
    const connectionManager = new ConnectionManager(konvaManager.getLayer(), konvaManager.getStage(), nodeManager.nodes);
    konvaManager.setConnectionManager(connectionManager); // Set reference after instantiation
    const propertiesPanelManager = new PropertiesPanelManager(konvaManager.getLayer(), connectionManager);
    const toolbarManager = new ToolbarManager(nodeManager, konvaManager.getTransformer(), propertiesPanelManager);
    const uiManager = new UIManager(konvaManager.getStage());
    const modelManager = new ModelManager(nodeManager, connectionManager, konvaManager);
    window.modelManager = modelManager; // Make it global for event handlers
    const threatModelGenerator = new ThreatModelGenerator(konvaManager.getLayer(), connectionManager.connections, nodeManager, uiManager, modelManager);
    const exportManager = new ExportManager(threatModelGenerator.analysisResultContainer, () => threatModelGenerator.getThreatModelJSON(), threatModelGenerator.convertJsonToMarkdown.bind(threatModelGenerator), uiManager);

    exportManager.initialize('export-btn', 'export-menu');

    // Make exportModel available globally for HTML onclick handlers
    window.exportModel = (format) => exportManager.exportModel(format);

    window.addEventListener('portClicked', (e) => {
        connectionManager.startConnection(e.detail.group, e.detail.port);
    });
    
    Split(['#toolbar', '#graph-container', '#properties-panel'], {
        sizes: [15, 60, 25], minSize: [150, 300, 300], gutterSize: 8,
    });

    console.log('Split initialized');
});