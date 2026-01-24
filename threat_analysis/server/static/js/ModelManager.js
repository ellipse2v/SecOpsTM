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
// threat_analysis/server/static/js/ModelManager.js

class ModelManager {
    constructor(nodeManager, connectionManager, konvaManager) {
        this.nodeManager = nodeManager;
        this.connectionManager = connectionManager;
        this.konvaManager = konvaManager; // Store konvaManager
        this.openModelModal = document.getElementById('open-model-modal');
        this.openModelBtn = document.getElementById('open-model-btn');
        this.closeBtn = this.openModelModal.querySelector('.close-button');
        this.modelListContainer = document.getElementById('model-list-container');
        this.refreshModelsBtn = document.getElementById('refresh-models-btn');
        this.openFromComputerBtn = document.getElementById('open-from-computer-btn');
        this.fileInput = document.getElementById('file-input');
        this.protocolStyles = {};

        this.setupEventHandlers();
    }

    setupEventHandlers() {
        this.openModelBtn.onclick = () => {
            this.openModelModal.style.display = 'block';
            this.fetchModels();
        };
        this.closeBtn.onclick = () => {
            this.openModelModal.style.display = 'none';
        };
        window.onclick = (event) => {
            if (event.target == this.openModelModal) {
                this.openModelModal.style.display = 'none';
            }
        };
        this.refreshModelsBtn.onclick = () => this.fetchModels();
        this.openFromComputerBtn.onclick = () => {
            this.fileInput.click();
        };
        this.fileInput.onchange = (event) => this.handleFileUpload(event);
    }

    handleFileUpload(event) {
        const files = event.target.files;
        if (files.length === 0) {
            return;
        }

        let markdownFile = null;
        let metadataFile = null;

        for (let i = 0; i < files.length; i++) {
            if (files[i].name.endsWith('.md')) {
                markdownFile = files[i];
                break;
            }
        }

        if (!markdownFile) {
            alert('Please select a markdown (.md) file.');
            return;
        }

        const expectedMetadataName = markdownFile.name.replace('.md', '_metadata.json');
        for (let i = 0; i < files.length; i++) {
            if (files[i].name === expectedMetadataName) {
                metadataFile = files[i];
                break;
            }
        }
        
        if (!metadataFile) {
            for (let i = 0; i < files.length; i++) {
                if (files[i].name.endsWith('.json')) {
                    metadataFile = files[i];
                    break;
                }
            }
        }

        const markdownReader = new FileReader();
        markdownReader.onload = (e) => {
            const markdownContent = e.target.result;

            if (metadataFile) {
                const metadataReader = new FileReader();
                metadataReader.onload = (me) => {
                    try {
                        const metadataContent = JSON.parse(me.target.result);
                        this.repopulateGraph(markdownContent, metadataContent);
                        this.openModelModal.style.display = 'none';
                    } catch (jsonError) {
                        alert('Error parsing metadata file. Loading model without metadata.');
                        this.repopulateGraph(markdownContent, null);
                        this.openModelModal.style.display = 'none';
                    }
                };
                metadataReader.readAsText(metadataFile);
            } else {
                alert("No metadata file was selected.\n\nPlease select both the .md file and its corresponding _metadata.json file at the same time to load the positions.");
                this.repopulateGraph(markdownContent, null);
                this.openModelModal.style.display = 'none';
            }
        };
        markdownReader.readAsText(markdownFile);
        
        // Reset file input to allow selecting the same file again
        this.fileInput.value = null;
    }

    fetchModels() {
        this.modelListContainer.innerHTML = '<p>Loading models...</p>';
        fetch('/api/models')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    this.modelListContainer.innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                    return;
                }
                this.modelListContainer.innerHTML = '';
                if (data.models.length === 0) {
                    this.modelListContainer.innerHTML = '<p>No saved models found.</p>';
                } else {
                    data.models.forEach(modelPath => {
                        const item = document.createElement('div');
                        item.className = 'model-list-item';
                        item.textContent = modelPath;
                        item.onclick = () => this.loadModel(modelPath);
                        this.modelListContainer.appendChild(item);
                    });
                }
            })
            .catch(error => {
                console.error('Error fetching models:', error);
                this.modelListContainer.innerHTML = '<p style="color: red;">Failed to fetch models.</p>';
            });
    }

    loadModel(modelPath) {
        fetch('/api/load_model', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model_path: modelPath })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert(`Error loading model: ${data.error}`);
                return;
            }
            this.repopulateGraph(data.markdown_content, data.metadata);
            this.openModelModal.style.display = 'none';
        })
        .catch(error => {
            console.error('Error loading model:', error);
            alert('Failed to load model.');
        });
    }

    repopulateGraph(markdown, metadata) {
        this.parseProtocolStyles(markdown);
        // Clear existing graph
        const layer = this.konvaManager.getLayer();
        const children = layer.getChildren();
        for (let i = children.length - 1; i >= 0; i--) {
            const child = children[i];
            if (child !== this.konvaManager.transformer) {
                child.destroy();
            }
        }

        this.konvaManager.transformer.nodes([]);
        this.nodeManager.nodes = [];
        
        [...this.connectionManager.connections].forEach(conn => conn.destroy());
        this.connectionManager.connections = [];

        this.konvaManager.getLayer().draw();

        if (metadata && metadata.nodes && metadata.edges) {
            this.repopulateGraphFromMetadata(metadata);
        } else {
            let processedPositions = null;
            if (metadata && metadata.positions) {
                processedPositions = {};
                for (const category in metadata.positions) {
                    processedPositions[category] = {};
                    for (const name in metadata.positions[category]) {
                        const lookupName = this.sanitizeName(name).toLowerCase();
                        processedPositions[category][lookupName] = metadata.positions[category][name];
                    }
                }
            }

            fetch('/api/markdown_to_json', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ markdown: markdown })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert(`Error converting model: ${data.error}`);
                    return;
                }
                this.drawGraphFromJSON(data.model_json, processedPositions);
            })
            .catch(error => {
                console.error('Error converting model:', error);
                alert('Failed to convert model.');
            });
        }
    }

    drawGraphFromJSON(modelData, positions) {
        const getPosition = (type, name) => {
            let searchKey = `${type.toLowerCase()}s`;
            if (type.toLowerCase() === 'boundary') {
                searchKey = 'boundaries';
            } else if (type.toLowerCase() === 'data') {
                searchKey = 'data';
            }
            const sanitizedName = this.sanitizeName(name).toLowerCase();
            
            if (positions && positions[searchKey] && positions[searchKey][sanitizedName]) {
                const pos = positions[searchKey][sanitizedName];
                return pos;
            }
            return { x: 50, y: 50, width: null, height: null };
        };

        const idToNameMap = {};
        
        (modelData.boundaries || []).forEach(b => {
            const pos = getPosition('boundary', b.name);
            const node = this.nodeManager.addNode('BOUNDARY', b.name, pos.x, pos.y, pos.width, pos.height, b);
            idToNameMap[b.name] = node.id();
        });

        ['actors', 'servers'].forEach(type => {
            (modelData[type] || []).forEach(el => {
                let stereotype;
                let elementType;
                if (type === 'data') {
                    stereotype = 'DATA';
                    elementType = 'data';
                } else {
                    stereotype = el.stereotype || type.slice(0, -1).toUpperCase();
                    elementType = type.slice(0, -1);
                }
                const pos = getPosition(elementType, el.name);
                const node = this.nodeManager.addNode(stereotype, el.name, pos.x, pos.y, pos.width, pos.height, el);
                idToNameMap[el.name] = node.id();
            });
        });

        (modelData.dataflows || []).forEach(df => {
            const fromNode = this.konvaManager.getLayer().findOne('#' + idToNameMap[df.from]);
            const toNode = this.konvaManager.getLayer().findOne('#' + idToNameMap[df.to]);
            if (fromNode && toNode) {
                //const conn = this.connectionManager.startConnection(fromNode);
                const dummyPort = new Konva.Circle({ x: 0, y: 0, radius: 0, visible: false });
                fromNode.add(dummyPort);
                const conn = this.connectionManager.startConnection(fromNode, dummyPort);
                conn.attach(toNode);
                if (df.properties) {
                    Object.assign(conn.properties, df.properties);
                    conn.updateLabel();
                    conn.arrow.stroke(df.properties.color || '#000');
                    conn.arrow.fill(df.properties.color || '#000');
                    if (this.protocolStyles[conn.properties.protocol]) {
                        const styles = this.protocolStyles[conn.properties.protocol];
                        conn.properties.color = styles.color || conn.properties.color;
                        conn.properties.line_style = styles.line_style || conn.properties.line_style;
                        conn.updateStyle();
                    }
                } else {
                    conn.updateLabel();
                }
            }
        });

        this.connectionManager.activeConnection = null; // Reset active connection after all connections are drawn
        this.konvaManager.getLayer().draw();
    }

    sanitizeName(name) {
        if (!name) return "unnamed";
        let sanitized = name.replace(/[^a-zA-Z0-9_]/g, '_');
        if (sanitized && /^U/.test(sanitized)) {
            sanitized = '_' + sanitized;
        }
        return sanitized || "unnamed";
    }

    parseProtocolStyles(markdown) {
        this.protocolStyles = {};
        if (!markdown) return;
        const protocolStylesSection = markdown.match(/## Protocol Styles\n([\s\S]*?)(?=\n##|$)/);
        if (protocolStylesSection) {
            const lines = protocolStylesSection[1].split('\n');
            lines.forEach(line => {
                if (line.startsWith('- **')) {
                    const match = line.match(/- \*\*(.*?)\*\*: (.*)/);
                    if (match) {
                        const protocol = match[1].trim();
                        const styles = match[2].trim().split(', ');
                        const styleObj = {};
                        styles.forEach(style => {
                            const [key, value] = style.split('=');
                            styleObj[key.trim()] = value.trim();
                        });
                        this.protocolStyles[protocol] = styleObj;
                    }
                }
            });
        }
    }
    
    repopulateGraphFromMetadata(metadata) {
        // Create nodes
        (metadata.nodes || []).forEach(nodeData => {
            this.nodeManager.addNode(nodeData.type.toUpperCase(), nodeData.name, nodeData.x, nodeData.y, nodeData.width, nodeData.height, nodeData);
        });

        // Create connections
        (metadata.edges || []).forEach(edgeData => {
            const fromNode = this.nodeManager.nodes.find(n => n.getAttr('threatModelProperties').name === edgeData.source);
            const toNode = this.nodeManager.nodes.find(n => n.getAttr('threatModelProperties').name === edgeData.destination);
            
            if (fromNode && toNode) {
                const dummyPort = new Konva.Circle({ x: 0, y: 0, radius: 0, visible: false });
                fromNode.add(dummyPort);
                const conn = this.connectionManager.startConnection(fromNode, dummyPort, edgeData);
                conn.attach(toNode);
                
                if (edgeData.styles) {
                    conn.arrow.stroke(edgeData.styles.stroke || '#000');
                    conn.arrow.fill(edgeData.styles.stroke || '#000');
                }

                if (this.protocolStyles[conn.properties.protocol]) {
                    const styles = this.protocolStyles[conn.properties.protocol];
                    conn.properties.color = styles.color || conn.properties.color;
                    conn.properties.line_style = styles.line_style || conn.properties.line_style;
                    conn.updateStyle();
                }
            }
        });
        
        this.connectionManager.activeConnection = null;
        this.konvaManager.getLayer().draw();
    }
}