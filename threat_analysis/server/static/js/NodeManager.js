// threat_analysis/server/static/js/NodeManager.js

class NodeManager {
    constructor(layer, tr) {
        this.layer = layer;
        this.tr = tr;
        this.nodes = [];
    }

    addNode(type, name, x, y, newWidth, newHeight) {
        const config = ThreatModelConfig;
        const dimensions = config.ELEMENT_DIMENSIONS[type] || { width: 120, height: 80 };
        const colors = config.COLOR_SCHEMES[type] || config.COLOR_SCHEMES.DEFAULT;
        const defaultProps = config.DEFAULT_PROPERTIES[type] || {};
        
        const width = newWidth || dimensions.width || (type === 'BOUNDARY' ? 300 : 120);
        const height = newHeight || dimensions.height || (type === 'BOUNDARY' ? 200 : 80);
        const fill = colors.fill;
        const stroke = colors.stroke;
        const textColor = colors.text;
        const iconPath = ThreatModelConfig.ICON_MAPPING[type.toLowerCase().replace('_', '')];

        const group = new Konva.Group({
            x: x,
            y: y,
            draggable: true,
            name: type,
            id: 'id_' + Math.random().toString(36).substr(2, 9),
        });
        
        group.isNode = true;

        let shape;
        let text;
        const PADDING = 10;
        const TEXT_HEIGHT = 12;

        const isNetworkDevice = ['FIREWALL', 'SWITCH', 'ROUTER'].includes(type);
        
        if (type === 'ACTOR') {
            const radiusX = width / 2;
            const radiusY = height / 2;
            
            shape = new Konva.Ellipse({
                x: width / 2,
                y: height / 2,
                radiusX: radiusX,
                radiusY: radiusY,
                fill: fill,
                stroke: fill,
                strokeWidth: 2,
                name: 'shape',
            });
            
            text = new Konva.Text({
                x: 0,
                y: height + PADDING / 2,
                text: name,
                fontSize: TEXT_HEIGHT,
                fill: textColor,
                width: width,
                align: 'center',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                name: 'label',
            });
            
            if (iconPath) {
                Konva.Image.fromURL(iconPath, (image) => {
                    image.setAttrs({
                        x: (width - 48) / 2,
                        y: (height - 48) / 2,
                        width: 48,
                        height: 48,
                        listening: false,
                        name: 'image',
                    });
                    group.add(image);
                    this.layer.draw();
                });
            }
        } else if (isNetworkDevice) {
            const iconSize = type === 'SWITCH' ? 59 : 64;
            
            if (type === 'FIREWALL') {
                shape = new Konva.RegularPolygon({
                    x: width / 2,
                    y: iconSize / 2,
                    sides: 6,
                    radius: iconSize / 2,
                    fill: fill,
                    stroke: fill,
                    strokeWidth: 2,
                    name: 'shape',
                });
            } else {
                const shapeSize = type === 'SWITCH' ? iconSize + 5 : iconSize;
                shape = new Konva.Rect({
                    x: (width - shapeSize) / 2,
                    y: (iconSize - shapeSize) / 2,
                    width: shapeSize,
                    height: shapeSize,
                    fill: fill,
                    stroke: fill,
                    strokeWidth: 2,
                    name: 'shape',
                });
            }
            
            text = new Konva.Text({
                x: 0,
                y: iconSize + 5,
                text: name,
                fontSize: TEXT_HEIGHT,
                fill: textColor,
                width: width,
                align: 'center',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                name: 'label',
            });
            
            if (iconPath) {
                Konva.Image.fromURL(iconPath, (image) => {
                    image.setAttrs({
                        x: (width - iconSize) / 2,
                        y: 0,
                        width: iconSize,
                        height: iconSize,
                        listening: false,
                        name: 'image',
                    });
                    group.add(image);
                    this.layer.draw();
                });
            }
        } else if (type === 'DATABASE') {
            const iconSize = 64;
            const shapeHeight = 80;
            
            shape = new Konva.Rect({
                x: 0,
                y: 0,
                width: width,
                height: shapeHeight,
                fill: fill,
                stroke: fill,
                strokeWidth: 2,
                name: 'shape',
            });
            
            text = new Konva.Text({
                x: PADDING,
                y: shapeHeight + 5,
                text: name,
                fontSize: TEXT_HEIGHT,
                fill: textColor,
                width: width - 2 * PADDING,
                align: 'center',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                name: 'label',
            });
            
            if (iconPath) {
                Konva.Image.fromURL(iconPath, (image) => {
                    image.setAttrs({
                        x: (width - iconSize) / 2,
                        y: (shapeHeight - iconSize) / 2,
                        width: iconSize,
                        height: iconSize,
                        listening: false,
                        name: 'icon',
                    });
                    group.add(image);
                    this.layer.draw();
                });
            }
        } else if (type === 'WEB_SERVER') {
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
                x: PADDING,
                y: (height - TEXT_HEIGHT) / 2,
                text: name,
                fontSize: TEXT_HEIGHT,
                fill: textColor,
                width: width - 2 * PADDING,
                align: 'center',
                verticalAlign: 'middle',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                name: 'label',
            });
            
            if (iconPath) {
                Konva.Image.fromURL(iconPath, (image) => {
                    image.setAttrs({
                        x: width - 32,
                        y: height - 32,
                        width: 24,
                        height: 24,
                        listening: false,
                        name: 'icon',
                    });
                    group.add(image);
                    this.layer.draw();
                });
            }
        } else if (type === 'BOUNDARY') {
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
                x: 0,
                y: height + PADDING,
                text: name,
                fontSize: TEXT_HEIGHT,
                fill: textColor,
                width: width,
                align: 'left',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                name: 'label',
            });
        } else {
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
                x: PADDING,
                y: (height - TEXT_HEIGHT) / 2,
                text: name,
                fontSize: TEXT_HEIGHT,
                fill: textColor,
                width: width - 2 * PADDING,
                align: 'center',
                verticalAlign: 'middle',
                fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
                name: 'label',
            });
            
            if (iconPath && type !== 'ACTOR') {
                Konva.Image.fromURL(iconPath, (image) => {
                    image.setAttrs({
                        x: width - 32,
                        y: height - 32,
                        width: 24,
                        height: 24,
                        listening: false,
                        name: 'icon',
                    });
                    group.add(image);
                    this.layer.draw();
                });
            }
        }
        
        group.add(shape);
        if (text) group.add(text);

        this.layer.add(group);
        this.layer.draw();

        const properties = {
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
            availability: defaultProps.availability || 'medium',
            color: fill,
        };

        group.setAttr('threatModelProperties', properties);
        
        if (properties.isFilled) {
            shape.fill(properties.color);
        } else {
            shape.fill('transparent');
        }
        
        if (type === 'BOUNDARY') {
            shape.stroke(properties.isTrusted ? '#adb5bd' : 'red');
            shape.strokeWidth(properties.isTrusted ? 2 : 1);
        } else {
            shape.stroke(properties.color);
        }

        group.on('click', (e) => {
            e.cancelBubble = true;
            this.tr.nodes([group]);
            this.tr.enabledAnchors([]);
            // updatePropertiesPanel(group);
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
                const event = new CustomEvent('portClicked', { detail: { group: group } });
                window.dispatchEvent(event);
            });
            
            group.add(port);
            ports.push(port);
        });

        group.showPorts = (show) => ports.forEach(p => p.visible(show));
        
        group.on('mouseenter', () => group.showPorts(true));
        group.on('mouseleave', () => group.showPorts(false));
        
        
        this.nodes.push(group);
        return group;
    }

    getNodesPositions() {
        const positions = { actors: {}, servers: {}, data: {}, boundaries: {} };
        this.nodes.forEach(node => {
            const type = node.name();
            const props = node.getAttr('threatModelProperties');
            const name = props.name;
            const sanitizedName = this.sanitizeName(name).toLowerCase();
            const rect = node.findOne('.shape').getClientRect();

            const pos = { x: node.x(), y: node.y(), width: rect.width, height: rect.height };

            if (type === 'ACTOR') {
                positions.actors[sanitizedName] = pos;
            } else if (['SERVER', 'WEB_SERVER', 'DATABASE', 'FIREWALL', 'ROUTER', 'SWITCH', 'API_GATEWAY'].includes(type)) {
                positions.servers[sanitizedName] = pos;
            } else if (type === 'DATA') {
                positions.data[sanitizedName] = pos;
            } else if (type === 'BOUNDARY') {
                positions.boundaries[sanitizedName] = pos;
            }
        });
        return positions;
    }

    sanitizeName(name) {
        if (!name) return "unnamed";
        let sanitized = name.replace(/[^a-zA-Z0-9_]/g, '_');
        if (sanitized && /^\d/.test(sanitized)) {
            sanitized = '_' + sanitized;
        }
        return sanitized || "unnamed";
    }
}