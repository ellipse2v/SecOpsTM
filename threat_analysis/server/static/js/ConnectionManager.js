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
// threat_analysis/server/static/js/ConnectionManager.js

class ConnectionManager {
    constructor(layer, stage, nodes) {
        this.layer = layer;
        this.stage = stage;
        this.nodes = nodes;
        this.connections = [];
        this.activeConnection = null;
        this.hoverNode = null;
        this.selectedConnection = null;
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        this.stage.on('mousemove', () => this.handleMouseMove());
        this.stage.on('mouseup', () => this.handleMouseUp());
        window.addEventListener('keydown', (e) => this.handleKeyDown(e));
        window.addEventListener('itemSelected', (e) => this.handleItemSelected(e));
        window.addEventListener('selectionCleared', () => this.handleSelectionCleared());
        window.addEventListener('nodeDragMove', () => this.updateAllConnections());
    }

    handleItemSelected(e) {
        const item = e.detail.item;
        if (item instanceof Connection) {
            this.selectConnection(item);
        } else {
            this.clearConnectionSelection();
        }
    }

    handleSelectionCleared() {
        this.clearConnectionSelection();
    }

    clearConnectionSelection() {
        if (this.selectedConnection) {
            this.selectedConnection.arrow.stroke('#000');
            this.selectedConnection.arrow.strokeWidth(2);
            this.selectedConnection = null;
            this.layer.draw();
        }
    }

    handleMouseMove() {
        if (!this.activeConnection) return;
        const pos = this.stage.getPointerPosition();
        if (!pos) return;

        // Get the starting port's absolute position
        const portAbsPos = this.activeConnection.clickedPort.getAbsolutePosition();
        
        this.activeConnection.arrow.points([
            portAbsPos.x,
            portAbsPos.y,
            pos.x,
            pos.y
        ]);

        const intersected = this.stage.getIntersection(pos);
        let targetNode = null;
        
        // Check if we intersected with a node (not the stage, not a port, not the source node)
        if (intersected) {
            let current = intersected;
            // Traverse up to find the parent group
            while (current && !current.isNode) {
                current = current.getParent();
            }
            if (current && current.isNode && current !== this.activeConnection.fromNode) {
                targetNode = current;
            }
        }

        // Clear all glows first
        this.nodes.forEach(n => this.setGlow(n, false));
        
        // Show glow and ports on hover
        if (targetNode) {
            this.hoverNode = targetNode;
            this.setGlow(this.hoverNode, true);
            this.hoverNode.showPorts(true);
        } else {
            if (this.hoverNode) {
                this.hoverNode.showPorts(false);
            }
            this.hoverNode = null;
        }
        this.layer.batchDraw();
    }

    handleMouseUp() {
        if (!this.activeConnection) return;
        if (this.hoverNode) {
            this.activeConnection.attach(this.hoverNode);
            this.hoverNode.showPorts(false);
        } else {
            this.activeConnection.destroy();
        }
        this.nodes.forEach(n => {
            this.setGlow(n, false);
            n.showPorts(false);
        });
        this.activeConnection = null;
        this.hoverNode = null;
        this.layer.draw();
    }

    handleKeyDown(e) {
        if ((e.key === 'Delete' || e.key === 'Backspace') && this.selectedConnection) {
            this.selectedConnection.destroy();
            this.selectedConnection = null;
            this.layer.draw();
            window.dispatchEvent(new CustomEvent('selectionCleared'));
        }
    }

    updateAllConnections() {
        this.connections.forEach(c => c.update());
        this.layer.batchDraw();
    }

    startConnection(n, clickedPort) {
        if (!clickedPort) {
        clickedPort = {
            getAbsolutePosition: () => {
                return {
                    x: n.getAbsolutePosition().x + n.width() / 2,
                    y: n.getAbsolutePosition().y + n.height() / 2
                };
            }
        };
    }
        this.activeConnection = new Connection(n, this, clickedPort);
        const uniqueName = this.findUniqueDataflowName('New Dataflow');
        this.activeConnection.properties.name = uniqueName;
        this.activeConnection.setLabel(uniqueName);
        return this.activeConnection;
    }
    
    setGlow(node, on) {
        const shapeNode = node.findOne('.shape');
        if (shapeNode) {
            shapeNode.shadowColor('#2196f3');
            shapeNode.shadowBlur(on ? 35 : 0);
            shapeNode.shadowOpacity(1);
            this.layer.batchDraw();
        }
    }

    recomputeConflicts(a, b) {
        const key = [a.id(), b.id()].sort().join('-');
        const group = this.connections.filter(c => {
            if (!c.toNode) return false;
            return [c.fromNode.id(), c.toNode.id()].sort().join('-') === key;
        });

        const mid = (group.length - 1) / 2;
        group.forEach((c, i) => {
            const dir = c.fromNode === a ? 1 : -1;
            c.offsetIndex = (i - mid) * dir;
            c.update();
        });
    }

    selectConnection(c) {
        this.clearConnectionSelection();

        this.selectedConnection = c;
        c.arrow.stroke('#1976d2');
        c.arrow.strokeWidth(3);
        this.layer.draw();
        window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: c } }));
    }

    findUniqueDataflowName(baseName) {
        const existingNames = new Set();
        this.connections.forEach(conn => {
            existingNames.add(conn.properties.name);
        });

        if (!existingNames.has(baseName)) {
            return baseName;
        }

        let i = 1;
        while (true) {
            const newName = `${baseName} ${i}`;
            if (!existingNames.has(newName)) {
                return newName;
            }
            i++;
        }
    }
}

class Connection {
    constructor(fromNode, manager, clickedPort) {
        this.fromNode = fromNode;
        this.toNode = null;
        this.offsetIndex = 0;
        this.manager = manager;
        this.clickedPort = clickedPort;
        this.properties = {
            name: 'New Dataflow',
            protocol: 'TCP',
            isEncrypted: false,
            isAuthenticated: false,
            description: '',
            color: '#000000',
            data: ''
        };
        this.labelText = this.properties.name;

        // Get the initial port position
        const portAbsPos = clickedPort.getAbsolutePosition();

        this.arrow = new Konva.Arrow({
            points: [portAbsPos.x, portAbsPos.y, portAbsPos.x, portAbsPos.y],
            stroke: '#000',
            fill: '#000',
            strokeWidth: 2,
            pointerLength: 10,
            pointerWidth: 10,
            name: 'connectionArrow'
        });

        this.hit = new Konva.Line({
            points: [portAbsPos.x, portAbsPos.y, portAbsPos.x, portAbsPos.y],
            stroke: 'transparent',
            strokeWidth: 12,
            name: 'connectionHit'
        });

        this.label = new Konva.Text({
            text: this.labelText,
            fontSize: 12,
            fill: '#000',
            padding: 2,
            background: '#fff',
            name: 'connectionLabel'
        });

        [this.arrow, this.hit, this.label].forEach(obj => {
            obj.on('click', (e) => {
                e.cancelBubble = true;
                this.manager.selectConnection(this);
            });
            this.manager.layer.add(obj);
        });

        this.manager.connections.push(this);
    }

    update() {
        if (!this.toNode) {
            // Temporary connection - already handled by handleMouseMove
            return;
        }

        const toCenter = {
            x: this.toNode.getAbsolutePosition().x + this.toNode.width() / 2,
            y: this.toNode.getAbsolutePosition().y + this.toNode.height() / 2
        };
        const fromCenter = {
            x: this.fromNode.getAbsolutePosition().x + this.fromNode.width() / 2,
            y: this.fromNode.getAbsolutePosition().y + this.fromNode.height() / 2
        };

        const p1 = this.getAnchor(this.fromNode, toCenter);
        const p2 = this.getAnchor(this.toNode, fromCenter);

        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const len = Math.hypot(dx, dy) || 1;
        const nx = -dy / len;
        const ny = dx / len;

        const spacing = 14;
        const off = this.offsetIndex * spacing;

        const a = {x: p1.x + nx * off, y: p1.y + ny * off};
        const b = {x: p2.x + nx * off, y: p2.y + ny * off};

        this.arrow.points([a.x, a.y, b.x, b.y]);
        this.hit.points([a.x, a.y, b.x, b.y]);

        this.label.position({
            x: (a.x + b.x) / 2,
            y: (a.y + b.y) / 2
        });
    }

    attach(node) {
        this.toNode = node;
        this.manager.recomputeConflicts(this.fromNode, this.toNode);
        this.update();
    }
    
    setLabel(text) {
        this.labelText = text;
        this.label.text(text);
        this.manager.layer.draw();
    }

    destroy() {
        [this.arrow, this.hit, this.label].forEach(obj => obj.destroy());
        const index = this.manager.connections.indexOf(this);
        if (index !== -1) {
            this.manager.connections.splice(index, 1);
        }
        if (this.toNode) {
            this.manager.recomputeConflicts(this.fromNode, this.toNode);
        }
    }

    getAnchor(node, targetPoint) {
        const group = node;
        const absPos = group.getAbsolutePosition();
        const shape = group.findOne('.shape');
        
        if (!shape) {
            return { x: absPos.x, y: absPos.y };
        }
        
        if (group.name() === 'ACTOR') {
            const radiusX = shape.radiusX();
            const radiusY = shape.radiusY();
            const center = {
                x: absPos.x + shape.x(),
                y: absPos.y + shape.y()
            };
            
            const angle = Math.atan2(targetPoint.y - center.y, targetPoint.x - center.x);
            return {
                x: center.x + radiusX * Math.cos(angle),
                y: center.y + radiusY * Math.sin(angle)
            };
        }

        const shapeAbsPos = shape.getAbsolutePosition();
        const w = shape.width();
        const h = shape.height();
        
        const center = {
            x: shapeAbsPos.x + w / 2,
            y: shapeAbsPos.y + h / 2,
        };

        const dx = targetPoint.x - center.x;
        const dy = targetPoint.y - center.y;
        
        if (Math.abs(dx) < 0.001 && Math.abs(dy) < 0.001) {
            return { x: center.x, y: center.y };
        }
        
        const halfW = w / 2;
        const halfH = h / 2;
        
        const tx = dx !== 0 ? (dx > 0 ? halfW / dx : -halfW / dx) : Infinity;
        const ty = dy !== 0 ? (dy > 0 ? halfH / dy : -halfH / dy) : Infinity;
        
        const t = Math.min(tx, ty);
        
        return {
            x: center.x + dx * t,
            y: center.y + dy * t
        };
    }
}