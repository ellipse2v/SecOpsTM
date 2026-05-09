// Threat Model Configuration - Web UI
// Generated on: 2026-05-08 20:30:38
// This file contains configuration for the threat model web interface

const ThreatModelConfig = {
    "ICON_MAPPING": {
        "actor": "/static/resources/icons/actor.svg",
        "data": "/static/resources/icons/data.svg",
        "router": "/static/resources/icons/routers.svg",
        "switch": "/static/resources/icons/switch.svg",
        "server": "/static/resources/icons/server.svg",
        "dmz": "/static/resources/icons/dmz.svg",
        "firewall": "/static/resources/icons/firewall.svg",
        "database": "/static/resources/icons/database.svg",
        "web_server": "/static/resources/icons/web-server.svg",
        "webserver": "/static/resources/icons/web-server.svg",
        "api_gateway": "/static/resources/icons/api-gateway.svg",
        "apigateway": "/static/resources/icons/api-gateway.svg",
        "load_balancer": "/static/resources/icons/load_balancer.svg",
        "loadbalancer": "/static/resources/icons/load_balancer.svg"
    },
    "DEFAULT_PROPERTIES": {
        "BOUNDARY": {
            "name": "New Boundary",
            "description": "",
            "isTrusted": true,
            "lineStyle": "solid",
            "isFilled": true,
            "color": "#f8f9fa"
        },
        "ACTOR": {
            "name": "New Actor",
            "description": "",
            "color": "#E9D5FF"
        },
        "DATA": {
            "name": "New Data",
            "description": "",
            "classification": "public",
            "format": "",
            "credentialsLife": "",
            "confidentiality": "medium",
            "integrity": "medium",
            "availability": "medium",
            "color": "#FFE0B2"
        },
        "SERVER": {
            "name": "New Server",
            "description": "",
            "os": "",
            "color": "#D1FAE5"
        },
        "WEB_SERVER": {
            "name": "Web Server",
            "description": "",
            "os": "",
            "color": "#D1FAE5"
        },
        "DATABASE": {
            "name": "Database",
            "description": "",
            "os": "",
            "color": "#D1FAE5"
        },
        "FIREWALL": {
            "name": "Firewall",
            "description": "",
            "os": "",
            "color": "#FFCDD2"
        },
        "ROUTER": {
            "name": "Router",
            "description": "",
            "os": "",
            "color": "#FFD700"
        },
        "SWITCH": {
            "name": "Switch",
            "description": "",
            "os": "",
            "color": "orange"
        }
    },
    "ELEMENT_DIMENSIONS": {
        "BOUNDARY": {
            "width": 200,
            "height": 150
        },
        "ACTOR": {
            "width": 80,
            "height": 80
        },
        "DATA": {
            "width": 100,
            "height": 70
        },
        "SERVER": {
            "width": 120,
            "height": 80
        },
        "WEB_SERVER": {
            "width": 120,
            "height": 80
        },
        "DATABASE": {
            "width": 120,
            "height": 100
        },
        "FIREWALL": {
            "width": 120,
            "height": 100
        },
        "ROUTER": {
            "width": 120,
            "height": 100
        },
        "SWITCH": {
            "width": 120,
            "height": 100
        }
    },
    "COLOR_SCHEMES": {
        "BOUNDARY": {
            "fill": "#f8f9fa",
            "stroke": "#adb5bd",
            "text": "#495057"
        },
        "ACTOR": {
            "fill": "#E9D5FF",
            "stroke": "#9333EA",
            "text": "#581C87"
        },
        "DATA": {
            "fill": "#FFE0B2",
            "stroke": "#E65100",
            "text": "#BF360C"
        },
        "DEFAULT": {
            "fill": "#D1FAE5",
            "stroke": "#065F46",
            "text": "#064E3B"
        },
        "FIREWALL": {
            "fill": "#FFCDD2",
            "stroke": "#B71C1C",
            "text": "#B71C1C"
        },
        "ROUTER": {
            "fill": "#FFD700",
            "stroke": "#B8860B",
            "text": "#8B4513"
        },
        "SWITCH": {
            "fill": "orange",
            "stroke": "#B8860B",
            "text": "#8B4513"
        }
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThreatModelConfig;
}
