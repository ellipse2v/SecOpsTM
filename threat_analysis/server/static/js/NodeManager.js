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
// threat_analysis/server/static/js/NodeManager.js

class NodeManager {
    constructor(layer, tr) {
        this.layer = layer;
        this.tr = tr;
        this.nodes = [];
    }

    addNode(type, name, x, y, newWidth, newHeight, incomingProps) {
        if (type) {
            type = type.toUpperCase();
        }
        const config = ThreatModelConfig;
        const dimensions = config.ELEMENT_DIMENSIONS[type] || { width: 120, height: 80 };
        const colors = config.COLOR_SCHEMES[type] || config.COLOR_SCHEMES.DEFAULT;
        const defaultProps = config.DEFAULT_PROPERTIES[type] || {};

        const baseProperties = {
            name: name || defaultProps.name || 'New Element',
            description: defaultProps.description || '',
            os: defaultProps.os || '',
            stereotype: type,
            isFilled: defaultProps.isFilled !== undefined ? defaultProps.isFilled : (type === 'BOUNDARY' ? false : true),
            isTrusted: defaultProps.isTrusted !== undefined ? defaultProps.isTrusted : (type === 'BOUNDARY' ? false : true),
            lineStyle: defaultProps.lineStyle || 'solid',
            format: defaultProps.format || '',
            credentialsLife: defaultProps.credentialsLife || '',
            classification: defaultProps.classification || 'public',
            confidentiality: defaultProps.confidentiality || 'medium',
            integrity: defaultProps.integrity || 'medium',
            availability: defaultProps.availability || 'medium'
        };
        
        const properties = { ...baseProperties, ...incomingProps };

        if (!properties.color) {
            properties.color = defaultProps.color || colors.fill;
        }

        const PADDING = 10;
        const tempText = new Konva.Text({ text: name, fontSize: 12, fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif' });
        const measuredWidth = tempText.width();
    
        let width = newWidth || dimensions.width || (type === 'BOUNDARY' ? 300 : 120);
        
        if (!newWidth && (measuredWidth + PADDING * 2) > width) {
            width = measuredWidth + PADDING * 2;
        }
        
        const height = newHeight || dimensions.height || (type === 'BOUNDARY' ? 200 : 80);
        const fill = properties.color;
        const stroke = colors.stroke;
        const textColor = colors.text;
        const iconPath = ThreatModelConfig.ICON_MAPPING[type.toLowerCase().replace('_', '')];

        const group = new Konva.Group({
            x: x,
            y: y,
            draggable: true,
            name: type,
            id: 'id_' + Math.random().toString(36).substr(2, 9),
            width: width,
            height: height,
        });

        if (type === 'FIREWALL') {
            const iconSize = 64;
            group.setAttr('hitFunc', function(context) {
                context.beginPath();
                context.rect(0, 0, iconSize, this.height());
                context.closePath();
                context.fillStrokeShape(this);
            });
        }
        
        group.isNode = true;

        let shape;
        let text;
        const TEXT_HEIGHT = 12;

        switch (type) {
            case 'ACTOR': {
                const radiusX = width / 2;
                const radiusY = height / 2;
                const radius = Math.min(width, height) / 2;
                shape = new Konva.Circle({
                    x: width / 2, y: height / 2, radius: radius,
                    fill: fill, stroke: fill, strokeWidth: 2, name: 'shape',
                });
                text = new Konva.Text({
                    x: width / 2, y: height + PADDING / 2, text: name, fontSize: TEXT_HEIGHT, fill: textColor,
                    align: 'center', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', name: 'label',
                    listening: false,
                    wrap: 'none'
                });
                text.offsetX(text.width() / 2);
                if (iconPath) {
                    Konva.Image.fromURL(iconPath, (image) => {
                        image.setAttrs({
                            x: (width - 48) / 2, y: (height - 48) / 2, width: 48, height: 48,
                            listening: false, name: 'image',
                        });
                        group.add(image);
                        this.layer.draw();
                    });
                }
                break;
            }
            case 'FIREWALL': {
                const iconSize = 64;
                shape = new Konva.RegularPolygon({
                    x: width / 2, y: iconSize / 2, sides: 6, radius: iconSize / 2,
                    fill: fill, stroke: fill, strokeWidth: 2, name: 'shape',
                });
                text = new Konva.Text({
                    x: width / 2, y: iconSize + 5, text: name, fontSize: TEXT_HEIGHT, fill: textColor,
                    align: 'center', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', name: 'label',
                    listening: false,
                    wrap: 'none'
                });
                text.offsetX(text.width() / 2);
                if (iconPath) {
                    Konva.Image.fromURL(iconPath, (image) => {
                        image.setAttrs({
                            x: (width - iconSize) / 2, y: 0, width: iconSize, height: iconSize,
                            listening: false, name: 'image',
                        });
                        group.add(image);
                        this.layer.draw();
                    });
                }
                break;
            }
            case 'ROUTER':
            case 'SWITCH': {
                const iconSize = type === 'SWITCH' ? 59 : 64;
                shape = new Konva.Rect({
                    x: 0,
                    y: 0,
                    width: width,
                    height: height,
                    fill: fill,
                    stroke: fill,
                    strokeWidth: 2,
                    name: 'shape',
                });
                text = new Konva.Text({
                    x: width / 2,
                    y: height + 5,
                    text: name,
                    fontSize: TEXT_HEIGHT,
                    fill: textColor,
                    align: 'center',
                    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                    name: 'label',
                    listening: false,
                    wrap: 'none'
                });
                text.offsetX(text.width() / 2);
                if (iconPath) {
                    Konva.Image.fromURL(iconPath, (image) => {
                        image.setAttrs({
                            x: (width - iconSize) / 2,
                            y: (height - iconSize) / 2,
                            width: iconSize,
                            height: iconSize,
                            listening: false,
                            name: 'image',
                        });
                        group.add(image);
                        this.layer.draw();
                    });
                }
                break;
            }
            case 'DATABASE': {
                const iconSize = 48;
                shape = new Konva.Shape({
                    sceneFunc: function (context, shape) {
                        const w = width;
                        const h = height;
                        const x = 0;
                        const y = 0;
                        const ellipseH = h * 0.2; // Height of the ellipse top/bottom

                        // Top ellipse
                        context.beginPath();
                        context.save();
                        context.scale(1, 0.5);
                        context.arc(x + w / 2, (y + ellipseH / 2) / 0.5, w / 2, 0, 2 * Math.PI);
                        context.restore();
                        context.fillStrokeShape(shape);

                        // Cylinder body
                        context.beginPath();
                        context.rect(x, y + ellipseH / 2, w, h - ellipseH);
                        context.fillStrokeShape(shape);
                        
                        // Bottom ellipse
                        context.beginPath();
                        context.save();
                        context.scale(1, 0.5);
                        context.arc(x + w / 2, (y + h - ellipseH / 2) / 0.5, w / 2, 0, 2 * Math.PI);
                        context.restore();
                        context.fillStrokeShape(shape);
                    },
                    width: width,
                    height: height,
                    name: 'shape',
                    fill: fill,
                    stroke: stroke,
                    strokeWidth: 2,
                });
                
                group.scaleX(0.5);
                group.scaleY(0.5);

                text = new Konva.Text({
                    x: PADDING,
                    y: height / 2 - TEXT_HEIGHT / 2,
                    text: name,
                    fontSize: TEXT_HEIGHT * 2,
                    fill: textColor,
                    width: width - 2 * PADDING,
                    align: 'center',
                    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                    name: 'label',
                    listening: false,
                });
                
                if (iconPath) {
                    Konva.Image.fromURL(iconPath, (image) => {
                        image.setAttrs({
                            x: (width - iconSize) / 2,
                            y: (height - iconSize) / 2,
                            width: iconSize,
                            height: iconSize,
                            listening: false,
                            name: 'image',
                        });
                        group.add(image);
                        this.layer.draw();
                    });
                }
                break;
            }
            case 'WEB_SERVER': {
                shape = new Konva.Rect({
                    x: 0, y: 0, width: width, height: height,
                    fill: fill, stroke: fill, strokeWidth: 2, name: 'shape',
                });
                text = new Konva.Text({
                    x: PADDING, y: (height - TEXT_HEIGHT) / 2, text: name, fontSize: TEXT_HEIGHT, fill: textColor,
                    width: width - 2 * PADDING, align: 'center', verticalAlign: 'middle',
                    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', name: 'label',
                    listening: false,
                });
                if (iconPath) {
                    Konva.Image.fromURL(iconPath, (image) => {
                        image.setAttrs({
                            x: width - 32, y: height - 32, width: 24, height: 24,
                            listening: false, name: 'icon',
                        });
                        group.add(image);
                        this.layer.draw();
                    });
                }
                break;
            }
            case 'BOUNDARY': {
                shape = new Konva.Rect({
                    x: 0, y: 0, width: width, height: height,
                    fill: fill, stroke: fill, strokeWidth: 2, name: 'shape', cornerRadius: 10,
                });
                text = new Konva.Text({
                    x: 0, y: height + PADDING, text: name, fontSize: TEXT_HEIGHT, fill: textColor,
                    align: 'left', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', name: 'label',
                    listening: false,
                    wrap: 'none'
                });
                break;
            }
            default: {
                shape = new Konva.Rect({
                    x: 0, y: 0, width: width, height: height,
                    fill: fill, stroke: fill, strokeWidth: 2, name: 'shape',
                });
                text = new Konva.Text({
                    x: PADDING, y: (height - TEXT_HEIGHT) / 2, text: name, fontSize: TEXT_HEIGHT, fill: textColor,
                    width: width - 2 * PADDING, align: 'center', verticalAlign: 'middle',
                    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif', name: 'label',
                    listening: false,
                    wrap: 'none'
                });
                if (iconPath && type !== 'ACTOR') {
                    Konva.Image.fromURL(iconPath, (image) => {
                        image.setAttrs({
                            x: width - 32, y: height - 32, width: 24, height: 24,
                            listening: false, name: 'icon',
                        });
                        group.add(image);
                        this.layer.draw();
                    });
                }
                break;
            }
        }
        
        group.add(shape);
        if (text) group.add(text);

        this.layer.add(group);
        this.layer.draw();

        group.setAttr('threatModelProperties', properties);
        
        if (properties.isFilled) {
            shape.fill(properties.color);
        } else {
            shape.fill('transparent');
        }
        
        if (type === 'BOUNDARY') {
            if (properties.isFilled) {
                shape.fill(properties.color);
            } else {
                shape.fill('transparent');
            }

            if (properties.isTrusted) {
                shape.stroke('red');
            } else {
                shape.stroke(properties.color || '#adb5bd'); // Use color, fallback to default
            }
            shape.strokeWidth(properties.isTrusted ? 2 : 1);

            if (properties.lineStyle === 'dashed') {
                shape.dash([10, 5]);
            } else if (properties.lineStyle === 'dotted') {
                shape.dash([2, 5]);
            } else {
                shape.dash([]); // Solid
            }
        } else {
            shape.fill(properties.color);
            shape.stroke(properties.color);
        }

        group.on('click', (e) => {
            console.log('NodeManager: node clicked', group.id(), group.name());
            e.cancelBubble = true;
            this.tr.nodes([group]);
            this.tr.moveToTop();
            this.tr.enabledAnchors([]);
            this.layer.draw();
            window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: group } }));
        });

        group.on('dblclick dbltap', (e) => {
            console.log('NodeManager: node dblclicked', group.id(), group.name());
            e.cancelBubble = true;
            this.tr.nodes([group]);
            this.tr.moveToTop();
            this.tr.enabledAnchors(['top-left', 'top-right', 'bottom-left', 'bottom-right']);
            this.tr.rotateEnabled(false);
            this.tr.borderEnabled(true);
            this.layer.draw();
            window.dispatchEvent(new CustomEvent('itemSelected', { detail: { item: group } }));
        });

        group.on('transform', () => {
            const textNode = group.findOne('.label');
            if (textNode) {
                textNode.scaleX(1 / group.scaleX());
                textNode.scaleY(1 / group.scaleY());
            }
            const iconNode = group.findOne('.image') || group.findOne('.icon');
            if (iconNode) {
                iconNode.scaleX(1 / group.scaleX());
                iconNode.scaleY(1 / group.scaleY());
            }

            // Inverse scale for ports to keep them the same size
            group.find('.port').forEach(port => {
                port.scaleX(1 / group.scaleX());
                port.scaleY(1 / group.scaleY());
            });
        });

        const ports = [];
        const portOffset = 8;
        
        const portPositions = [
            {x: width/2, y: -portOffset},
            {x: width + portOffset, y: height/2},
            {x: width/2, y: height + portOffset},
            {x: -portOffset, y: height/2}
        ];

        portPositions.forEach(p => {
            const port = new Konva.Circle({
                x: p.x,
                y: p.y,
                radius: 6,
                fill: '#fff',
                stroke: '#1976d2',
                strokeWidth: 2,
                visible: false,
                cursor: 'crosshair',
                name: 'port',
                shadowColor: 'rgba(0,0,0,0.3)',
                shadowBlur: 3,
                shadowOffset: {x: 1, y: 1}
            });
            
            port.on('mousedown', (e) => {
                e.cancelBubble = true;
                const event = new CustomEvent('portClicked', { detail: { group: group, port: port } });
                window.dispatchEvent(event);
            });
            
            group.add(port);
            ports.push(port);
        });

        group.showPorts = (show) => ports.forEach(p => p.visible(show));
        
        group.on('mouseenter', () => group.showPorts(true));
        group.on('mouseleave', () => group.showPorts(false));
        
        group.on('dragmove', () => {
            this.layer.batchDraw(); // Redraw the layer during node drag
            window.dispatchEvent(new CustomEvent('nodeDragMove', { detail: { node: group } }));
        });

        this.nodes.push(group);
        return group;
    }

    findUniqueName(baseName) {
        const existingNames = new Set();
        this.layer.find('Group').forEach(group => {
                    if (group.id() && group.getAttr('threatModelProperties')) {
                        existingNames.add(group.getAttr('threatModelProperties').name);
                    }
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

    getNodesPositions() {
        const positions = { actors: {}, servers: {}, data: {}, boundaries: {} };
        this.nodes.forEach(node => {
            const type = node.name();
            const props = node.getAttr('threatModelProperties');
            const name = props.name;
            let sanitizedName = this.sanitizeName(name);
            // Capitalize first letter for consistency with mode simple
            if (sanitizedName.length > 0) {
                sanitizedName = sanitizedName.charAt(0).toUpperCase() + sanitizedName.slice(1);
            }
            const rect = node.findOne('.shape').getClientRect();

            const pos = { x: node.x(), y: node.y(), width: rect.width, height: rect.height };

            if (type === 'ACTOR') {
                positions.actors[sanitizedName] = pos;
            } else if (type === 'DATA') {
                positions.data[sanitizedName] = pos;
            } else if (type === 'BOUNDARY') {
                positions.boundaries[sanitizedName] = pos;
            } else {
                // Default to servers for all other types (app_server, load_balancer, etc.)
                positions.servers[sanitizedName] = pos;
            }
        });
        return positions;
    }

    sanitizeName(name) {
        if (!name) return "unnamed";
        let sanitized = name.replace(/[^a-zA-Z0-9_ ]/g, '_');
        if (sanitized && /^\d/.test(sanitized)) {
            sanitized = '_' + sanitized;
        }
        return sanitized || "unnamed";
    }
}