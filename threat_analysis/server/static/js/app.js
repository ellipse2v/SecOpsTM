// threat_analysis/server/static/js/App.js

document.addEventListener('DOMContentLoaded', () => {
    const konvaManager = new KonvaManager('graph-container');
    const nodeManager = new NodeManager(konvaManager.getLayer(), konvaManager.getTransformer());
    const connectionManager = new ConnectionManager(konvaManager.getLayer(), konvaManager.getStage(), nodeManager.nodes);
    konvaManager.setConnectionManager(connectionManager); // Set reference after instantiation
    const propertiesPanelManager = new PropertiesPanelManager(konvaManager.getTransformer(), connectionManager);
    const toolbarManager = new ToolbarManager(nodeManager, propertiesPanelManager);
    const threatModelGenerator = new ThreatModelGenerator(konvaManager.getLayer(), connectionManager.connections, nodeManager);
    const exportManager = new ExportManager(threatModelGenerator.analysisResultContainer, () => threatModelGenerator.getThreatModelJSON(), threatModelGenerator.convertJsonToMarkdown);
    const modelManager = new ModelManager(nodeManager, connectionManager, konvaManager);

    exportManager.initialize('export-btn', 'export-menu');

    window.addEventListener('portClicked', (e) => {
        connectionManager.startConnection(e.detail.group);
    });
    
    Split(['#toolbar', '#graph-container', '#properties-panel'], {
        sizes: [15, 60, 25], minSize: [150, 300, 300], gutterSize: 8,
    });
});