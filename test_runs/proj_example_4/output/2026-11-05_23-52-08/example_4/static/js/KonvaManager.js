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

        this.stage.on('mousedown', (e) => this.handleMouseDown(e));
        this.stage.on('mousemove', (e) => this.handleMouseMove(e));
        this.stage.on('mouseup', () => this.handleMouseUp());

        this.stage.on('wheel', (e) => this.handleZoom(e));
        this.stage.on('click tap', (e) => this.handleSelection(e));
        this.stage.on('dblclick dbltap', (e) => this.handleDblClick(e));
        window.addEventListener('keydown', (e) => this.handleKeyDown(e));
    }

    handleMouseDown(e) {
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

        // Do nothing if clicked on transformer or its handles
        if (e.target.findAncestor(n => n.getClassName() === 'Transformer') || e.target.getClassName() === 'Transformer') {
            return;
        }

        // Check if we clicked on a connection element
        const targetName = e.target.name();
        if (targetName === 'connectionArrow' || targetName === 'connectionHit' || targetName === 'connectionLabel') {
            // Connection clicked - the click handler on the connection itself will handle selection
            this.transformer.nodes([]); // Clear node selection
            return;
        }

        // Find the group (node) if we clicked on a shape or anything inside it
        let group = e.target.hasName('shape') ? e.target.getParent() : e.target.findAncestor(n => n.getClassName() === 'Group' && (n.isNode || n.getAttr('isNode')));
        
        // Check if it's really a node group (should have isNode property set in NodeManager)
        if (group && (group.isNode || group.getAttr('isNode'))) {
            const selectedNodes = this.transformer.nodes();
            if (selectedNodes.length !== 1 || selectedNodes[0].id() !== group.id()) {
                this.transformer.nodes([group]);
                this.transformer.moveToTop();
            }
            window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: group } }));
        } else {
            // If we clicked on something else that is not the stage,
            // but not a node or connection, clear selection
            this.transformer.nodes([]);
            window.dispatchEvent(new CustomEvent('selectionCleared'));
        }
    }

    handleDblClick(e) {
        console.log('KonvaManager: handleDblClick', e.target.getClassName(), e.target.name());
        let group = e.target.hasName('shape') ? e.target.getParent() : e.target.findAncestor(n => n.getClassName() === 'Group' && (n.isNode || n.getAttr('isNode')));
        
        // If we double-clicked on the transformer itself, use its attached node
        if (!group && (e.target.findAncestor(n => n.getClassName() === 'Transformer') || e.target.getClassName() === 'Transformer')) {
            const attachedNodes = this.transformer.nodes();
            if (attachedNodes.length > 0) {
                group = attachedNodes[0];
            }
        }

        if (group && group.id()) {
            console.log('KonvaManager: found group to dblclick', group.id());
            this.transformer.nodes([group]);
            this.transformer.moveToTop();
            this.transformer.enabledAnchors(['top-left', 'top-right', 'bottom-left', 'bottom-right']);
            this.transformer.rotateEnabled(false);
            this.transformer.borderEnabled(true);
            this.layer.draw();
            window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: group } }));
        } else {
            console.log('KonvaManager: no group found for dblclick');
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
                    window.dispatchEvent(new CustomEvent('nodeDeleted'));
                }
            }
            // Note: Connection deletion is handled in ConnectionManager
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