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
// threat_analysis/server/static/js/ThreatModelGenerator.js

class ThreatModelGenerator {
    constructor(layer, connections, nodeManager, uiManager, modelManager) {
        this.layer = layer;
        this.connections = connections;
        this.nodeManager = nodeManager; // Store nodeManager
        this.uiManager = uiManager;
        this.modelManager = modelManager;
        this.analysisResultContainer = document.getElementById('analysis-result-container');
        document.getElementById('analyze-btn').addEventListener('click', () => this.generate());
        this.threatModelJSON = {};
    }

    getThreatModelJSON() {
        this.threatModelJSON = this.collectModelData();
        return this.threatModelJSON;
    }

    collectModelData() {
        const elements = [];
        const boundaries = [];
        const actors = [];
        const servers = [];
        
        this.layer.find('Group').forEach(group => {
            if (group.id() && group.getAttr('threatModelProperties')) {
                const props = group.getAttr('threatModelProperties');
                const elementType = props.stereotype || group.name();
                
                const shape = group.findOne('.shape');
                const rect = shape.getClientRect();
                const element = {
                    id: group.id(),
                    name: props.name,
                    type: elementType,
                    x: group.x(),
                    y: group.y(),
                    width: rect.width,
                    height: rect.height,
                    properties: props
                };
                
                elements.push(element);
                
                const upperType = elementType.toUpperCase();
                if (upperType === 'BOUNDARY') { boundaries.push(element); }
                else if (upperType === 'ACTOR') { actors.push(element); }
                else { servers.push(element); } // Default to server for any other element with properties
            }
        });
        
        const connectionsData = (this.connections || []).map(conn => {
            if (!conn.toNode) return null;
            return {
                from: conn.fromNode.id(),
                to: conn.toNode.id(),
                type: 'connection',
                label: conn.labelText,
                properties: conn.properties
            };
        }).filter(Boolean);
        
        [...actors, ...servers].forEach(element => {
            const group_center = { x: element.x + element.width / 2, y: element.y + element.height / 2 };
            let parent_boundary = null;
            let smallest_area = Infinity;

            boundaries.forEach(boundary => {
                const bx = boundary.x;
                const by = boundary.y;
                const bw = boundary.width;
                const bh = boundary.height;
                if (group_center.x > bx && group_center.x < bx + bw &&
                    group_center.y > by && group_center.y < by + bh) {
                    const area = bw * bh;
                    if (area < smallest_area) {
                        smallest_area = area;
                        parent_boundary = boundary;
                    }
                }
            });
            if (parent_boundary) {
                element.parentId = parent_boundary.id;
            }
        });

        return {
            boundaries: boundaries,
            actors: actors,
            servers: servers,
            data: Object.entries(this.modelManager.dataDictionary).map(([name, props]) => ({
                name: name,
                properties: props
            })),
            elements: elements,
            connections: connectionsData
        };
    }

    generate() {
        if (this.uiManager) {
            this.uiManager.switchToTab('analysis');
        }
        try {
            console.log('Generate button clicked');
            
            this.threatModelJSON = this.collectModelData();
            
            // Generate debug info for the UI
            let debug_info = '<h3>Boundary-Element Overlap Debugging:</h3><table border="1"><tr><th>Element</th><th>Center (x,y)</th><th>Boundary</th><th>Bounds (x,y,w,h)</th><th>Contained?</th></tr>';
            [...this.threatModelJSON.actors, ...this.threatModelJSON.servers, ...this.threatModelJSON.data].forEach(element => {
                const group_center = { x: element.x + element.width / 2, y: element.y + element.height / 2 };
                
                this.threatModelJSON.boundaries.forEach(boundary => {
                    const bx = boundary.x;
                    const by = boundary.y;
                    const bw = boundary.width;
                    const bh = boundary.height;
                    let contained = (group_center.x > bx && group_center.x < bx + bw &&
                                    group_center.y > by && group_center.y < by + bh);
                    debug_info += `<tr><td>${element.name}</td><td>(${group_center.x.toFixed(2)}, ${group_center.y.toFixed(2)})</td><td>${boundary.name}</td><td>(${bx.toFixed(2)}, ${by.toFixed(2)}, ${bw.toFixed(2)}, ${bh.toFixed(2)})</td><td>${contained}</td></tr>`;
                });
            });
            debug_info += '</table>';
            
            const markdownContent = this.convertJsonToMarkdown(this.threatModelJSON);
            const modelName = this.getModelName(markdownContent);
            const positionsData = this.nodeManager.getNodesPositions(); // Get positions from NodeManager

            this.analysisResultContainer.innerHTML = `
                <h3>Generating...</h3>
                <div class="loading-spinner"></div>
                <p id="generation-progress-message"></p>
                <div id="ai-progress-container" style="display: none;">
                    <p id="ai-progress-message"></p>
                    <div class="progress-bar-container">
                        <div id="ai-progress-bar" class="progress-bar"></div>
                    </div>
                </div>
            `;
            const progressMessageElement = document.getElementById('generation-progress-message');
            const aiProgressContainer = document.getElementById('ai-progress-container');
            const aiProgressMessageElement = document.getElementById('ai-progress-message');
            const aiProgressBar = document.getElementById('ai-progress-bar');

            const eventSource = new EventSource('/api/ai_status_stream');

            eventSource.addEventListener('ai_progress', (e) => {
                const eventData = JSON.parse(e.data);
                if (eventData.status === 'ai_enrichment_started') {
                    progressMessageElement.textContent = eventData.message;
                    aiProgressContainer.style.display = 'block';
                } else if (eventData.status === 'ai_enrichment_progress') {
                    aiProgressMessageElement.textContent = eventData.message;
                    aiProgressBar.style.width = eventData.progress + '%';
                } else if (eventData.status === 'ai_enrichment_finished') {
                    progressMessageElement.textContent = 'AI enrichment complete, finishing up...';
                    aiProgressBar.style.width = '100%';
                }
            });

            eventSource.onerror = (err) => {
                console.error("EventSource failed:", err);
                eventSource.close();
            };

            fetch('/api/generate_all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    markdown: markdownContent,
                    model_name: modelName,
                    positions: positionsData,
                }),
            })
            .then(response => response.json())
            .then(data => {
                eventSource.close();
                if (data.error) {
                    alert('Error during generation:\n' + data.error);
                    this.analysisResultContainer.innerHTML = '<h3>Error during generation</h3><pre>' + data.error + '</pre>' + debug_info;
                    console.error('Generation error:', data.error);
                    return;
                }

                let filesHtml = '<ul>';
                for (const key in data.generated_files.reports) {
                    filesHtml += `<li>${key}: ${data.generated_files.reports[key]}</li>`;
                }
                for (const key in data.generated_files.diagrams) {
                    filesHtml += `<li>${key}: ${data.generated_files.diagrams[key]}</li>`;
                }
                filesHtml += `<li>model: ${data.generated_files.model}</li>`;
                filesHtml += `<li>metadata: ${data.generated_files.metadata}</li>`;
                filesHtml += '</ul>';

                this.analysisResultContainer.innerHTML = '<h3>Generation Successful</h3>' +
                    `<p>All artifacts generated in directory: ${data.generation_dir}</p>` +
                    '<h4>Generated Files:</h4>' +
                    filesHtml + debug_info;
            })
            .catch(error => {
                eventSource.close();
                alert('Network Error:\n' + error.message);
                this.analysisResultContainer.innerHTML = '<h3>Network Error</h3><pre>' + error.message + '</pre>' + debug_info;
                console.error('Network error:', error);
            });

        } catch (e) {
            this.analysisResultContainer.innerHTML = '<h3>Error during generation</h3><pre>' + e.stack + '</pre>';
            console.error("Error in generate function:", e);
        }
    }

    convertJsonToMarkdown(data) {
        const markdown_lines = ["# Threat Model: Graphical Editor"];

        const boundaries = data.boundaries || [];
        const actors = data.actors || [];
        const servers = data.servers || [];
        const data_elements = data.data || [];

        const boundary_map = boundaries.reduce((acc, b) => {
            acc[b.id] = b.name;
            return acc;
        }, {});

        const _format_properties = (item_properties, props_to_include) => {
            const props = [];
            for (const prop_key of props_to_include) {
                const prop_value = item_properties[prop_key];
                if (prop_value !== undefined && prop_value !== null && prop_value !== '') {
                    let value_str;
                    if (typeof prop_value === 'boolean') {
                        value_str = prop_value ? 'True' : 'False';
                        props.push(`${prop_key}=${value_str}`);
                    } else {
                        value_str = String(prop_value);
                        // Use quotes only if the value contains spaces or other special characters
                        if (value_str.includes(' ') || value_str.includes(',') || value_str.includes('=')) {
                            props.push(`${prop_key}="${value_str}"`);
                        } else {
                            props.push(`${prop_key}=${value_str}`);
                        }
                    }
                }
            }
            return props.join(', ');
        };

        markdown_lines.push("\n## Boundaries");
        for (const boundary of boundaries) {
            const props_str = _format_properties(boundary.properties, ['description', 'isTrusted', 'lineStyle', 'color', 'isFilled']);
            markdown_lines.push(`- **${boundary.name}**: ${props_str}`);
        }

        markdown_lines.push("\n## Actors");
        for (const actor of actors) {
            const boundary_name = actor.parentId ? boundary_map[actor.parentId] : '';
            const props = { ...actor.properties, boundary: boundary_name };
            const props_str = _format_properties(props, ['boundary', 'description', 'color', 'isFilled']);
            markdown_lines.push(`- **${actor.name}**: ${props_str}`);
        }

        markdown_lines.push("\n## Servers");
        for (const server of servers) {
            const boundary_name = server.parentId ? boundary_map[server.parentId] : '';
            const props = { ...server.properties, boundary: boundary_name, type: server.type };
            const props_str = _format_properties(props, ['boundary', 'type', 'description', 'os', 'color']);
            markdown_lines.push(`- **${server.name}**: ${props_str}`);
        }

        markdown_lines.push("\n## Data");
        for (const data_item of data_elements) {
            const props_str = _format_properties(data_item.properties, ['description', 'classification', 'format', 'credentialsLife', 'confidentiality', 'integrity', 'availability']);
            markdown_lines.push(`- **${data_item.name}**: ${props_str}`);
        }
        
        markdown_lines.push("\n## Protocol Styles");
        for (const protocol in this.modelManager.protocolStyles) {
            const styles = this.modelManager.protocolStyles[protocol];
            const styles_str = Object.entries(styles).map(([key, value]) => `${key}=${value}`).join(', ');
            markdown_lines.push(`- **${protocol}**: ${styles_str}`);
        }

        markdown_lines.push("\n## Dataflows");
        for (const conn of (data.connections || [])) {
            const from_element = (data.elements || []).find(e => e.id === conn.from);
            const to_element = (data.elements || []).find(e => e.id === conn.to);
            const from_name = from_element ? from_element.name : "Unknown Source";
            const to_name = to_element ? to_element.name : "Unknown Sink";
            
            const props_str = conn.properties ? _format_properties(conn.properties, ['protocol', 'isEncrypted', 'isAuthenticated', 'description', 'color', 'line_style', 'data']) : '';
            markdown_lines.push(`- **${(conn.properties || {}).name || conn.label || 'Unnamed Dataflow'}**: from="${from_name}", to="${to_name}", ${props_str}`);
        }

        return markdown_lines.join('\n');
    }

    getModelName(markdownContent) {
        const match = markdownContent.match(/^# Threat Model: (.*)$/m);
        return match ? match[1].trim() : "Untitled Model";
    }
}