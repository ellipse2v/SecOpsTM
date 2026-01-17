// threat_analysis/server/static/js/KonvaManager.js

class KonvaManager {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.stage = new Konva.Stage({
            container: containerId,
            width: this.container.offsetWidth,
            height: this.container.offsetHeight,
        });
        this.layer = new Konva.Layer();
        this.stage.add(this.layer);
        this.transformer = new Konva.Transformer({
            enabledAnchors: [],
            rotateEnabled: false,
            borderEnabled: true,
            anchorSize: 8,
            anchorCornerRadius: 4,
            anchorFill: '#4CAF50',
            anchorStroke: '#2E7D32',
            anchorStrokeWidth: 1,
            borderStroke: '#4CAF50',
            borderStrokeWidth: 2,
            borderDash: [3, 3],
            keepRatio: false,
            shouldOverdrawWholeArea: true,
        });
        this.layer.add(this.transformer);

        this.isPanning = false;
        this.lastPointerPosition = { x: 0, y: 0 };

        this.setupEventHandlers();
    }

    setConnectionManager(connectionManager) {
        this.connectionManager = connectionManager;
    }

    setupEventHandlers() {
        new ResizeObserver(() => {
            this.stage.width(this.container.offsetWidth);
            this.stage.height(this.container.offsetHeight);
        }).observe(this.container);

        // this.stage.draggable(true); // Disable Konva's built-in dragging
        this.stage.on('mousedown', (e) => this.handleMouseDown(e));
        this.stage.on('mousemove', (e) => this.handleMouseMove(e));
        this.stage.on('mouseup', () => this.handleMouseUp());

        this.stage.on('wheel', (e) => this.handleZoom(e));
        this.stage.on('click tap', (e) => this.handleSelection(e));
        this.stage.on('dblclick dbltap', (e) => this.handleDblClick(e));
        window.addEventListener('keydown', (e) => this.handleKeyDown(e));
    }

    handleMouseDown(e) {
        // Only start panning if clicking on empty stage with left mouse button
        if (e.target === this.stage && e.evt.button === 0) {
            this.isPanning = true;
            this.lastPointerPosition = this.stage.getPointerPosition();
        }
    }

    handleMouseMove(e) {
        if (this.isPanning) {
            const currentPointerPosition = this.stage.getPointerPosition();
            const dx = currentPointerPosition.x - this.lastPointerPosition.x;
            const dy = currentPointerPosition.y - this.lastPointerPosition.y;

            const newX = this.stage.x() + dx;
            const newY = this.stage.y() + dy;

            this.stage.position({ x: newX, y: newY });
            this.lastPointerPosition = currentPointerPosition;
            this.layer.batchDraw();
            if (this.connectionManager) {
                this.connectionManager.updateAllConnections();
            }
        }
    }

    handleMouseUp() {
        this.isPanning = false;
    }

    handleZoom(e) {
        e.evt.preventDefault();
        const scaleBy = 1.1;
        const oldScale = this.stage.scaleX();
        const pointer = this.stage.getPointerPosition();

        const mousePointTo = {
            x: (pointer.x - this.stage.x()) / oldScale,
            y: (pointer.y - this.stage.y()) / oldScale,
        };

        let direction = e.evt.deltaY > 0 ? -1 : 1;
        const newScale = direction > 0 ? oldScale * scaleBy : oldScale / scaleBy;

        this.stage.scale({ x: newScale, y: newScale });

        const newPos = {
            x: pointer.x - mousePointTo.x * newScale,
            y: pointer.y - mousePointTo.y * newScale,
        };
        this.stage.position(newPos);
    }

    handleSelection(e) {
        // If click on empty area, remove all transformers
        if (e.target === this.stage) {
            this.transformer.nodes([]);
            window.dispatchEvent(new CustomEvent('selectionCleared'));
            return;
        }

        // Do nothing if clicked on transformer
        if (e.target.getParent() && e.target.getParent().className === 'Transformer') {
            return;
        }

        // If we clicked on a shape that is not selectable, clear selection
        if (!e.target.hasName('shape') && !e.target.hasName('connectionLabel')) {
            this.transformer.nodes([]);
            window.dispatchEvent(new CustomEvent('selectionCleared'));
            return;
        }

        let selectedItem = null;
        if (e.target.hasName('shape')) {
            const group = e.target.getParent();
            if (group && group.id()) {
                // If multiple nodes are selected, deselect others and select only the clicked one
                const selectedNodes = this.transformer.nodes();
                if (selectedNodes.length > 1) {
                    this.transformer.nodes([group]);
                } else if (selectedNodes.length === 1 && selectedNodes[0].id() !== group.id()) {
                    this.transformer.nodes([group]);
                } else if (selectedNodes.length === 0) {
                    this.transformer.nodes([group]);
                }
                selectedItem = group;
            }
        } else if (e.target.hasName('connectionLabel')) {
            this.connectionManager.selectConnection(e.target.getParent());
            return; // Exit after direct selection to prevent further event dispatch
        }
        
        window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: selectedItem } }));
    }

    handleDblClick(e) {
        if (e.target.hasName('shape')) {
            const group = e.target.getParent();
            if (group && group.id()) {
                this.transformer.nodes([group]);
                this.transformer.enabledAnchors(['top-left', 'top-right', 'bottom-left', 'bottom-right']);
                this.transformer.rotateEnabled(false);
                this.transformer.borderEnabled(true);
                this.layer.draw();
                window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: group } }));
            }
        }
    }

    handleKeyDown(e) {
        if (e.key === 'Delete' || e.key === 'Backspace') {
            const selectedNodes = this.transformer.nodes();
            if (selectedNodes.length > 0) {
                const nodeType = selectedNodes[0].name();
                const nodeName = selectedNodes[0].findOne('.label') ?
                                selectedNodes[0].findOne('.label').text() : 'this element';

                let confirmDelete = true;
                if (nodeType === 'BOUNDARY') {
                    confirmDelete = confirm(`Delete boundary "${nodeName}"? This may affect contained elements.`);
                }

                if (confirmDelete) {
                    selectedNodes.forEach(node => {
                        node.destroy();
                    });
                    this.transformer.nodes([]);
                    this.layer.draw();
                    window.dispatchEvent(new CustomEvent('selectionCleared'));
                    window.dispatchEvent(new CustomEvent('nodeDeleted')); // Or with node ID
                }
            }
        }
    }

    getLayer() {
        return this.layer;
    }

    getStage() {
        return this.stage;
    }

    getTransformer() {
        return this.transformer;
    }
}