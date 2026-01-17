// threat_analysis/server/static/js/ThreatModelGenerator.js

class ThreatModelGenerator {
    constructor(layer, connections, nodeManager) {
        this.layer = layer;
        this.connections = connections;
        this.nodeManager = nodeManager; // Store nodeManager
        this.analysisResultContainer = document.getElementById('analysis-result-container');
        document.getElementById('analyze-btn').addEventListener('click', () => this.generate());
        this.threatModelJSON = {};
    }

    getThreatModelJSON() {
        return this.threatModelJSON;
    }

    generate() {
        try {
            console.log('Generate button clicked');
            
            const elements = [];
            const boundaries = [];
            const actors = [];
            const servers = [];
            const dataElements = [];
            
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
                    
                    if (elementType === 'BOUNDARY') { boundaries.push(element); }
                    else if (elementType === 'ACTOR') { actors.push(element); }
                    else if (elementType === 'DATA') { dataElements.push(element); }
                    else if (['SERVER', 'WEB_SERVER', 'DATABASE', 'FIREWALL', 'ROUTER', 'SWITCH', 'API_GATEWAY'].includes(elementType)) { servers.push(element); }
                }
            });
            
            const connectionsData = this.connections.map(conn => {
                if (!conn.toNode) return null;
                return { 
                    from: conn.fromNode.id(), 
                    to: conn.toNode.id(), 
                    type: 'connection', 
                    label: conn.labelText,
                    properties: conn.properties
                };
            }).filter(Boolean);
            
            let debug_info = '<h3>Boundary-Element Overlap Debugging:</h3><table border="1"><tr><th>Element</th><th>Center (x,y)</th><th>Boundary</th><th>Bounds (x,y,w,h)</th><th>Contained?</th></tr>';
            [...actors, ...servers, ...dataElements].forEach(element => {
                const group_center = { x: element.x + element.width / 2, y: element.y + element.height / 2 };
                let parent_boundary = null;
                let smallest_area = Infinity;

                boundaries.forEach(boundary => {
                    const bx = boundary.x;
                    const by = boundary.y;
                    const bw = boundary.width;
                    const bh = boundary.height;
                    let contained = false;
                    if (group_center.x > bx && group_center.x < bx + bw &&
                        group_center.y > by && group_center.y < by + bh) {
                        contained = true;
                        const area = bw * bh;
                        if (area < smallest_area) {
                            smallest_area = area;
                            parent_boundary = boundary;
                        }
                    }
                    debug_info += `<tr><td>${element.name}</td><td>(${group_center.x.toFixed(2)}, ${group_center.y.toFixed(2)})</td><td>${boundary.name}</td><td>(${bx.toFixed(2)}, ${by.toFixed(2)}, ${bw.toFixed(2)}, ${bh.toFixed(2)})</td><td>${contained}</td></tr>`;
                });
                if (parent_boundary) {
                    element.parentId = parent_boundary.id;
                }
            });
            debug_info += '</table>';

            this.threatModelJSON = {
                boundaries: boundaries,
                actors: actors,
                servers: servers,
                data: dataElements,
                elements: elements,
                connections: connectionsData
            };
            
            const markdownContent = this.convertJsonToMarkdown(this.threatModelJSON);
            const modelName = this.getModelName(markdownContent);
            const positionsData = this.nodeManager.getNodesPositions(); // Get positions from NodeManager

            this.analysisResultContainer.innerHTML = '<h3>Generating...</h3><div class="loading-spinner"></div>';

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
                    props.push(`${prop_key}="${prop_value}"`);
                }
            }
            return props.join(', ');
        };

        markdown_lines.push("\n## Boundaries");
        for (const boundary of boundaries) {
            const props_str = _format_properties(boundary.properties, ['description', 'isTrusted', 'lineStyle']);
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
        
        markdown_lines.push("\n## Dataflows");
        for (const conn of (data.connections || [])) {
            const from_name = (data.elements.find(e => e.id === conn.from) || {}).name;
            const to_name = (data.elements.find(e => e.id === conn.to) || {}).name;
            const props_str = conn.properties ? _format_properties(conn.properties, ['protocol', 'isEncrypted', 'isAuthenticated', 'description', 'color', 'data']) : '';
            markdown_lines.push(`- **${(conn.properties || {}).name || conn.label}**: from="${from_name}", to="${to_name}", ${props_str}`);
        }

        return markdown_lines.join('\n');
    }

    getModelName(markdownContent) {
        const match = markdownContent.match(/^# Threat Model: (.*)$/m);
        return match ? match[1].trim() : "Untitled Model";
    }
}
