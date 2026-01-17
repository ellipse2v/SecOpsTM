// threat_analysis/server/static/js/ToolbarManager.js

class ToolbarManager {
    constructor(nodeManager, propertiesPanelManager) {
        this.nodeManager = nodeManager;
        this.propertiesPanelManager = propertiesPanelManager;
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        document.getElementById('add-boundary').addEventListener('click', () => {
            const group = this.nodeManager.addNode('BOUNDARY', this.nodeManager.findUniqueName('New Boundary'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-actor').addEventListener('click', () => {
            const group = this.nodeManager.addNode('ACTOR', this.nodeManager.findUniqueName('New Actor'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-server').addEventListener('click', () => {
            const group = this.nodeManager.addNode('SERVER', this.nodeManager.findUniqueName('New Server'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-web-server').addEventListener('click', () => {
            const group = this.nodeManager.addNode('WEB_SERVER', this.nodeManager.findUniqueName('Web Server'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-database').addEventListener('click', () => {
            const group = this.nodeManager.addNode('DATABASE', this.nodeManager.findUniqueName('Database'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-firewall').addEventListener('click', () => {
            const group = this.nodeManager.addNode('FIREWALL', this.nodeManager.findUniqueName('Firewall'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-router').addEventListener('click', () => {
            const group = this.nodeManager.addNode('ROUTER', this.nodeManager.findUniqueName('Router'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
        document.getElementById('add-switch').addEventListener('click', () => {
            const group = this.nodeManager.addNode('SWITCH', this.nodeManager.findUniqueName('New Switch'), 50, 50);
            this.nodeManager.tr.nodes([group]);
            this.propertiesPanelManager.updatePropertiesPanel(group);
        });
    }
}