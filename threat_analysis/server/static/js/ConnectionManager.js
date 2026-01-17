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
        // this.stage.on('dragmove', () => this.updateAllConnections()); // Removed, KonvaManager handles this now
        window.addEventListener('keydown', (e) => this.handleKeyDown(e));
        window.addEventListener('itemSelected', (e) => this.handleItemSelected(e));
        window.addEventListener('selectionCleared', () => this.handleSelectionCleared());
    }

    handleItemSelected(e) {
        const item = e.detail.item;
        if (item instanceof Connection) {
            this.selectConnection(item);
        } else {
            // If a node is selected, ensure connection selection is cleared
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

        const fromPos = this.activeConnection.fromNode.getAbsolutePosition();
        this.activeConnection.arrow.points([
            fromPos.x,
            fromPos.y,
            pos.x,
            pos.y
        ]);

        const intersected = this.stage.getIntersection(pos);
        const targetNode = intersected ? intersected.getParent() : null;

        this.nodes.forEach(n => this.setGlow(n, false));
        if (targetNode && targetNode.isNode && targetNode !== this.activeConnection.fromNode) {
            this.hoverNode = targetNode;
            this.setGlow(this.hoverNode, true);
        } else {
            this.hoverNode = null;
        }
        this.layer.batchDraw();
    }

    handleMouseUp() {
        if (!this.activeConnection) return;
        if (this.hoverNode) {
            this.activeConnection.attach(this.hoverNode);
        } else {
            this.activeConnection.destroy();
        }
        this.nodes.forEach(n => this.setGlow(n, false));
        this.activeConnection = null;
        this.hoverNode = null;
        this.layer.draw();
    }

    handleKeyDown(e) {
        if (e.key === 'Delete' && this.selectedConnection) {
            this.selectedConnection.destroy();
            this.selectedConnection = null;
            this.layer.draw();
            window.dispatchEvent(new CustomEvent('selectionCleared')); // Notify properties panel
        }
    }

    updateAllConnections() {
        this.connections.forEach(c => c.update());
    }

    startConnection(n) {
        this.activeConnection = new Connection(n, this);
        const uniqueName = this.findUniqueDataflowName('New Dataflow');
        this.activeConnection.properties.name = uniqueName;
        this.activeConnection.setLabel(uniqueName);
        return this.activeConnection; // Return the new connection
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
        this.clearConnectionSelection(); // Clear any previous connection selection

        this.selectedConnection = c;
        c.arrow.stroke('#1976d2');
        c.arrow.strokeWidth(3);
        this.layer.draw();
        // window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: c } })); // Removed to prevent infinite loop
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
    constructor(fromNode, manager) {
        this.fromNode = fromNode;
        this.toNode = null;
        this.offsetIndex = 0;
        this.manager = manager;
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

        this.arrow = new Konva.Arrow({
            stroke: '#000',
            fill: '#000',
            strokeWidth: 2,
            pointerLength: 10,
            pointerWidth: 10
        });

        this.hit = new Konva.Line({
            stroke: 'transparent',
            strokeWidth: 12
        });

        this.label = new Konva.Text({
            text: this.labelText,
            fontSize: 12,
            fill: '#000',
            padding: 2,
            background: '#fff'
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
        if (!this.toNode) return;

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