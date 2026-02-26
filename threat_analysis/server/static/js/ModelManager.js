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
        this.dataDictionary = {};

        this.dataModal = document.getElementById('data-manager-modal');
        this.dataListContainer = document.getElementById('data-list-container');
        this.saveDataItemBtn = document.getElementById('save-data-item-btn');
        this.newDataItemBtn = document.getElementById('new-data-item-btn');
        this.closeDataModalBtn = document.getElementById('close-data-modal');

        this.setupEventHandlers();
        this.loadDataDictionary();
    }

    setupEventHandlers() {
        if (this.closeDataModalBtn) {
            this.closeDataModalBtn.onclick = () => {
                this.dataModal.style.display = 'none';
            };
        }

        if (this.saveDataItemBtn) {
            this.saveDataItemBtn.onclick = () => {
                const nameInput = document.getElementById('data-name');
                const name = nameInput.value.trim();
                if (!name) return;

                this.dataDictionary[name] = {
                    description: document.getElementById('data-description').value,
                    classification: document.getElementById('data-classification').value,
                    format: document.getElementById('data-format').value,
                    credentialsLife: document.getElementById('data-credentials-life').value
                };
                this.renderDataList();
                this.updateDataflowDropdowns();
            };
        }

        if (this.newDataItemBtn) {
            this.newDataItemBtn.onclick = () => {
                this.clearDataForm();
            };
        }
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
        fetch('/api/models', {
            headers: {
                'X-Request-Start': performance.now()
            }
        })
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
        console.log(`[ModelManager] loadModel called for path: ${modelPath}`);
        fetch('/api/load_model', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Request-Start': performance.now()
            },
            body: JSON.stringify({ model_path: modelPath })
        })
        .then(response => response.json())
        .then(data => {
            console.log('[ModelManager] Received response from /api/load_model:', data);
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
        console.log('[ModelManager] repopulateGraph called.');
        this.parseProtocolStyles(markdown);
        this.parseDataDictionaryFromMarkdown(markdown);
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
        this.connectionManager.connections.length = 0; // Clear the array instead of replacing it

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
                        const lookupName = this.sanitizeName(name);
                        processedPositions[category][lookupName] = metadata.positions[category][name];
                        // Also store lowercase version for robust lookup
                        processedPositions[category][lookupName.toLowerCase()] = metadata.positions[category][name];
                        // Also store capitalized version for robust lookup
                        if (lookupName.length > 0) {
                            const capitalized = lookupName.charAt(0).toUpperCase() + lookupName.slice(1);
                            processedPositions[category][capitalized] = metadata.positions[category][name];
                        }
                    }
                }
            }

            console.log('[ModelManager] Fetching /api/markdown_to_json...');
            fetch('/api/markdown_to_json', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Request-Start': performance.now()
                },
                body: JSON.stringify({ markdown: markdown })
            })
            .then(response => response.json())
            .then(data => {
                console.log('[ModelManager] Received response from /api/markdown_to_json:', data);
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
        console.log('[ModelManager] drawGraphFromJSON called.');
        const getPosition = (type, name) => {
            let searchKey = `${type.toLowerCase()}s`;
            if (type.toLowerCase() === 'boundary') {
                searchKey = 'boundaries';
            } else if (type.toLowerCase() === 'data') {
                searchKey = 'data';
            }
            const sanitizedName = this.sanitizeName(name);
            
            if (positions && positions[searchKey]) {
                // Try exact match first
                if (positions[searchKey][sanitizedName]) {
                    return positions[searchKey][sanitizedName];
                }
                // Try case-insensitive match
                if (positions[searchKey][sanitizedName.toLowerCase()]) {
                    return positions[searchKey][sanitizedName.toLowerCase()];
                }
                // Try capitalized match
                const capitalized = sanitizedName.charAt(0).toUpperCase() + sanitizedName.slice(1);
                if (positions[searchKey][capitalized]) {
                    return positions[searchKey][capitalized];
                }
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
                stereotype = el.stereotype || type.slice(0, -1).toUpperCase();
                elementType = type.slice(0, -1);
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

        const event = new CustomEvent('modelLoaded', {
            detail: {
                modelData: modelData,
                message: 'Threat model has been successfully loaded and drawn on the canvas.'
            }
        });
        window.dispatchEvent(event);
    }

    sanitizeName(name) {
        if (!name) return "unnamed";
        let sanitized = name.replace(/[^a-zA-Z0-9_ ]/g, '_');
        if (sanitized && /^\d/.test(sanitized)) {
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

    parseDataDictionaryFromMarkdown(markdown) {
        if (!markdown) return;
        const dataSection = markdown.match(/## Data\n([\s\S]*?)(?=\n##|$)/);
        if (dataSection) {
            const lines = dataSection[1].split('\n');
            lines.forEach(line => {
                if (line.startsWith('- **')) {
                    const match = line.match(/- \*\*(.*?)\*\*: (.*)/);
                    if (match) {
                        const name = match[1].trim();
                        const propsStr = match[2].trim();
                        const props = {};
                        // Simple regex to match key="value" or key=value
                        const propMatches = propsStr.matchAll(/(\w+)=["']?([^"',]+)["']?/g);
                        for (const propMatch of propMatches) {
                            props[propMatch[1]] = propMatch[2];
                        }
                        this.dataDictionary[name] = {
                            description: props.description || "",
                            classification: props.classification || "public",
                            format: props.format || "",
                            credentialsLife: props.credentialsLife || ""
                        };
                    }
                }
            });
            this.updateDataflowDropdowns();
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

    loadDataDictionary() {
        fetch('/api/data_dictionary', {
            headers: {
                'X-Request-Start': performance.now()
            }
        })
            .then(response => response.text())
            .then(xmlString => {
                const parser = new DOMParser();
                const xmlDoc = parser.parseFromString(xmlString, "text/xml");
                const dataNodes = xmlDoc.getElementsByTagName("Data");
                
                for (let i = 0; i < dataNodes.length; i++) {
                    const node = dataNodes[i];
                    const name = node.getAttribute("name");
                    this.dataDictionary[name] = {
                        description: node.getAttribute("description") || "",
                        classification: node.getAttribute("classification") || "public",
                        format: node.getAttribute("format") || "",
                        credentialsLife: node.getAttribute("credentialsLife") || ""
                    };
                }
                this.updateDataflowDropdowns();
            })
            .catch(error => console.error('Error loading data dictionary:', error));
    }

    renderDataList() {
        if (!this.dataListContainer) return;
        this.dataListContainer.innerHTML = '';
        Object.keys(this.dataDictionary).sort().forEach(name => {
            const item = this.dataDictionary[name];
            const div = document.createElement('div');
            div.className = 'model-list-item';
            div.style.display = 'flex';
            div.style.justifyContent = 'space-between';
            div.style.alignItems = 'center';
            div.innerHTML = `
                <span><strong>${name}</strong> (${item.classification})</span>
                <div>
                    <button class="export-btn" style="padding: 4px 8px; margin: 0 2px;" onclick="window.modelManager.editDataItem('${name}')">Edit</button>
                    <button class="export-btn" style="padding: 4px 8px; margin: 0 2px; background-color: #f44336;" onclick="window.modelManager.deleteDataItem('${name}')">Delete</button>
                </div>
            `;
            this.dataListContainer.appendChild(div);
        });
    }

    editDataItem(name) {
        const item = this.dataDictionary[name];
        document.getElementById('data-name').value = name;
        document.getElementById('data-description').value = item.description;
        document.getElementById('data-classification').value = item.classification;
        document.getElementById('data-format').value = item.format;
        document.getElementById('data-credentials-life').value = item.credentialsLife;
    }

    deleteDataItem(name) {
        if (confirm(`Delete ${name}?`)) {
            delete this.dataDictionary[name];
            this.renderDataList();
            this.updateDataflowDropdowns();
        }
    }

    clearDataForm() {
        document.getElementById('data-name').value = '';
        document.getElementById('data-description').value = '';
        document.getElementById('data-classification').value = 'public';
        document.getElementById('data-format').value = '';
        document.getElementById('data-credentials-life').value = '';
    }

    updateDataflowDropdowns() {
        const dataSelect = document.getElementById('prop-data');
        if (!dataSelect) return;

        const currentValue = dataSelect.value;
        dataSelect.innerHTML = '<option value="">-- No Data --</option>';
        Object.keys(this.dataDictionary).sort().forEach(name => {
            const option = document.createElement('option');
            option.value = name;
            option.textContent = name;
            dataSelect.appendChild(option);
        });
        dataSelect.value = currentValue;
    }

    openDataManager() {
        this.renderDataList();
        this.dataModal.style.display = 'block';
    }
}
