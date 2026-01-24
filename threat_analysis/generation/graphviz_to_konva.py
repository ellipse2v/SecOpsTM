"""
Module pour extraire les métadonnées des diagrammes Graphviz 
et les convertir au format Konva
"""
import json
import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class GraphvizToKonvaConverter:
    """Convertit les SVG Graphviz en métadonnées Konva"""
    
    def __init__(self):
        self.svg_ns = {'svg': 'http://www.w3.org/2000/svg'}
        
    def extract_metadata_from_svg(self, svg_path: Path) -> Optional[Dict]:
        """
        Extrait les métadonnées d'un SVG Graphviz pour les rendre 
        compatibles avec Konva
        """
        try:
            tree = ET.parse(svg_path)
            root = tree.getroot()
            
            metadata = {
                'version': '1.0',
                'generator': 'graphviz',
                'nodes': [],
                'edges': [],
                'boundaries': [],
                'canvas': self._extract_canvas_info(root)
            }
            
            # Extraire les groupes (nodes, edges, clusters)
            for g in root.findall('.//svg:g', self.svg_ns):
                g_class = g.get('class', '')
                g_id = g.get('id', '')
                
                if g_class == 'node':
                    node_data = self._extract_node_metadata(g)
                    if node_data:
                        metadata['nodes'].append(node_data)
                        
                elif g_class == 'edge':
                    edge_data = self._extract_edge_metadata(g)
                    if edge_data:
                        metadata['edges'].append(edge_data)
                        
                elif g_class == 'cluster' or g_id.startswith('cluster_'):
                    boundary_data = self._extract_boundary_metadata(g)
                    if boundary_data:
                        metadata['boundaries'].append(boundary_data)
            
            return metadata
            
        except Exception as e:
            logging.error(f"Erreur lors de l'extraction des métadonnées: {e}")
            return None
    
    def _extract_canvas_info(self, root: ET.Element) -> Dict:
        """Extrait les informations sur le canvas depuis le SVG"""
        viewbox = root.get('viewBox', '0 0 800 600')
        parts = viewbox.split()
        
        return {
            'x': float(parts[0]) if len(parts) > 0 else 0,
            'y': float(parts[1]) if len(parts) > 1 else 0,
            'width': float(parts[2]) if len(parts) > 2 else 800,
            'height': float(parts[3]) if len(parts) > 3 else 600
        }
    
    def _extract_node_metadata(self, g: ET.Element) -> Optional[Dict]:
        """Extrait les métadonnées d'un nœud"""
        try:
            node_id = g.get('id', '')
            title = g.find('.//svg:title', self.svg_ns)
            node_name = title.text if title is not None else node_id
            
            # Extraire la forme (ellipse, polygon, rect, etc.)
            shape_element = None
            shape_type = 'rect'  # Par défaut
            
            for shape in ['ellipse', 'polygon', 'rect', 'path']:
                shape_element = g.find(f'.//svg:{shape}', self.svg_ns)
                if shape_element is not None:
                    shape_type = shape
                    break
            
            if shape_element is None:
                return None
            
            # Extraire position et dimensions
            position, dimensions = self._extract_shape_bounds(shape_element, shape_type)
            
            # Extraire le texte/label
            text_element = g.find('.//svg:text', self.svg_ns)
            label = self._extract_text_content(text_element) if text_element is not None else node_name
            
            # Extraire les styles
            styles = self._extract_node_styles(shape_element)
            
            # Déterminer le type de nœud à partir de l'ID ou des classes
            node_type = self._determine_node_type(node_id, label or '')
            
            return {
                'id': node_id,
                'name': node_name,
                'type': node_type,
                'x': position['x'],
                'y': position['y'],
                'width': dimensions['width'],
                'height': dimensions['height'],
                'shape': shape_type,
                'label': label,
                'styles': styles
            }
            
        except Exception as e:
            logging.warning(f"Erreur extraction nœud: {e}")
            return None
    
    def _extract_edge_metadata(self, g: ET.Element) -> Optional[Dict]:
        """Extract edge metadata from SVG group element"""
        try:
            edge_id = g.get('id', '')
            title = g.find('.//svg:title', self.svg_ns)
            
            # Parse title to get source and destination
            # Typical format: "source->destination"
            source, dest = '', ''
            if title is not None and title.text and '->' in title.text:
                parts = title.text.split('->')
                source = parts[0].strip()
                dest = parts[1].strip()
            
            # Extract edge path
            path = g.find('.//svg:path', self.svg_ns)
            if path is None:
                return None
            
            path_data = path.get('d', '')
            points = self._parse_path_to_points(path_data)
            
            # Extract ALL <text> elements with their attributes
            text_elements = g.findall('.//svg:text', self.svg_ns)
            labels_data = []
            label_lines = []
            
            all_lines = []
            for text_element in text_elements:
                # Get all text parts from the <text> element and its children (<tspan>)
                lines = [t.strip() for t in text_element.itertext() if t.strip()]
                if lines:
                    all_lines.extend(lines)
                    
                    # Also populate labels_data with the best possible coordinates
                    base_y = float(text_element.get('y', 0))
                    # crude font size based line height approx
                    line_height = float(text_element.get('font-size', 8.0))
                    
                    for i, line in enumerate(lines):
                         labels_data.append({
                            'text': line,
                            'x': float(text_element.get('x', 0)),
                            'y': base_y + i * line_height,
                            'font_family': text_element.get('font-family', 'Times,serif'),
                            'font_size': float(text_element.get('font-size', 7.0)),
                            'text_anchor': text_element.get('text-anchor', 'middle')
                        })

            label = '\n'.join(all_lines) if all_lines else ''

            # Extract styles
            styles = self._extract_edge_styles(path)
            
            # Extract protocol from label or classes
            protocol = self._extract_protocol(label, g.get('class', ''))
            
            return {
                'id': edge_id,
                'source': source,
                'destination': dest,
                'points': points,
                'label': label,
                'labels': labels_data,  # New detailed labels
                'protocol': protocol,
                'styles': styles
            }
            
        except Exception as e:
            logging.warning(f"Error extracting edge: {e}")
            return None
    
    def _extract_boundary_metadata(self, g: ET.Element) -> Optional[Dict]:
        """Extrait les métadonnées d'une boundary (cluster)"""
        try:
            boundary_id = g.get('id', '').replace('cluster_', '')
            logging.info(f"--- [BOUNDARY] Processing boundary with id: {boundary_id}")
            logging.info(f"--- [BOUNDARY] Cluster XML content: {ET.tostring(g, encoding='unicode')}")
            
            # Extraire le polygone, rectangle ou path de la boundary
            polygon = g.find('.//svg:polygon', self.svg_ns)
            rect = g.find('.//svg:rect', self.svg_ns)
            path = g.find('.//svg:path', self.svg_ns)
            
            shape_element = polygon or rect or path

            if shape_element is None:
                logging.warning(f"--- [BOUNDARY] No shape (polygon, rect, or path) found for boundary id: {boundary_id}")
                return None
            
            # Extraire position et dimensions
            bounds = self._extract_boundary_bounds(shape_element)
            
            # Extraire le label
            text_element = g.find('.//svg:text', self.svg_ns)
            label = self._extract_text_content(text_element) if text_element is not None else boundary_id
            logging.info(f"--- [BOUNDARY] Extracted label: {label}")
            
            # Extraire les styles
            styles = self._extract_boundary_styles(shape_element)
            
            # Détecter si c'est une boundary trusted
            is_trusted = 'trusted' in boundary_id.lower() or \
                        styles.get('stroke', '') == 'red'
            
            return {
                'id': boundary_id,
                'name': label,
                'x': bounds['x'],
                'y': bounds['y'],
                'width': bounds['width'],
                'height': bounds['height'],
                'isTrusted': is_trusted,
                'styles': styles
            }
            
        except Exception as e:
            logging.warning(f"Erreur extraction boundary: {e}")
            return None
    
    def _extract_shape_bounds(self, element: ET.Element, shape_type: str) -> Tuple[Dict, Dict]:
        """Extrait position et dimensions selon le type de forme"""
        if shape_type == 'ellipse':
            cx = float(element.get('cx', 0))
            cy = float(element.get('cy', 0))
            rx = float(element.get('rx', 50))
            ry = float(element.get('ry', 30))
            return (
                {'x': cx - rx, 'y': cy - ry},
                {'width': rx * 2, 'height': ry * 2}
            )
            
        elif shape_type == 'rect':
            return (
                {'x': float(element.get('x', 0)), 'y': float(element.get('y', 0))},
                {'width': float(element.get('width', 100)), 'height': float(element.get('height', 50))}
            )
            
        elif shape_type == 'polygon':
            points_str = element.get('points', '')
            points = self._parse_points(points_str)
            if not points:
                return ({'x': 0, 'y': 0}, {'width': 100, 'height': 50})
            
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            return (
                {'x': min(xs), 'y': min(ys)},
                {'width': max(xs) - min(xs), 'height': max(ys) - min(ys)}
            )
            
        return ({'x': 0, 'y': 0}, {'width': 100, 'height': 50})
    
    def _extract_boundary_bounds(self, element: ET.Element) -> Dict:
        """Extrait les bounds d'une boundary"""
        if element.tag.endswith('polygon'):
            points_str = element.get('points', '')
            points = self._parse_points(points_str)
            if not points:
                return {'x': 0, 'y': 0, 'width': 200, 'height': 200}
            
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            return {
                'x': min(xs),
                'y': min(ys),
                'width': max(xs) - min(xs),
                'height': max(ys) - min(ys)
            }
        elif element.tag.endswith('path'):
            path_data = element.get('d', '')
            points = self._parse_path_to_points(path_data)
            if not points:
                return {'x': 0, 'y': 0, 'width': 200, 'height': 200}
            
            xs = [p['x'] for p in points]
            ys = [p['y'] for p in points]
            return {
                'x': min(xs),
                'y': min(ys),
                'width': max(xs) - min(xs),
                'height': max(ys) - min(ys)
            }
        else:  # rect
            return {
                'x': float(element.get('x', 0)),
                'y': float(element.get('y', 0)),
                'width': float(element.get('width', 200)),
                'height': float(element.get('height', 200))
            }
    
    def _parse_points(self, points_str: str) -> List[Tuple[float, float]]:
        """Parse une chaîne de points SVG"""
        points = []
        pairs = points_str.strip().split()
        for pair in pairs:
            coords = pair.split(',')
            if len(coords) == 2:
                try:
                    points.append((float(coords[0]), float(coords[1])))
                except ValueError:
                    continue
        return points
    
    def _parse_path_to_points(self, path_data: str) -> List[Dict[str, float]]:
        """Convertit un path SVG en liste de points"""
        points = []
        
        # Extraire les commandes M (moveto) et L (lineto) et C (curve)
        commands = re.findall(r'[ML][\d\s,.-]+|C[\d\s,.-]+', path_data)
        
        for cmd in commands:
            cmd_type = cmd[0]
            coords = re.findall(r'-?\d+\.?\d*', cmd[1:])
            
            if cmd_type in ['M', 'L']:
                for i in range(0, len(coords), 2):
                    if i + 1 < len(coords):
                        points.append({
                            'x': float(coords[i]),
                            'y': float(coords[i + 1])
                        })
            elif cmd_type == 'C':
                # Pour les courbes, on prend juste le point de fin
                if len(coords) >= 6:
                    points.append({
                        'x': float(coords[4]),
                        'y': float(coords[5])
                    })
        
        return points
    
    def _extract_text_content(self, text_element: ET.Element) -> str:
        """Extrait le contenu textuel complet"""
        if text_element is None:
            return ''

        text_parts = []
        
        # Process top-level text element
        if text_element.text and text_element.text.strip():
            text_parts.append(text_element.text.strip())

        # Process tspan elements for multi-line text
        for tspan in text_element.findall('.//svg:tspan', self.svg_ns):
            if tspan.text and tspan.text.strip():
                text_parts.append(tspan.text.strip())
        
        return ' '.join(text_parts)
    
    def _extract_node_styles(self, element: ET.Element) -> Dict:
        """Extrait les styles d'un nœud"""
        styles = {}
        
        # Couleurs
        fill = element.get('fill')
        if fill:
            styles['fill'] = fill
            
        stroke = element.get('stroke')
        if stroke:
            styles['stroke'] = stroke
            
        stroke_width = element.get('stroke-width')
        if stroke_width:
            styles['strokeWidth'] = float(stroke_width)
        
        # Style depuis l'attribut style
        style_attr = element.get('style', '')
        if style_attr:
            style_pairs = style_attr.split(';')
            for pair in style_pairs:
                if ':' in pair:
                    key, value = pair.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'fill':
                        styles['fill'] = value
                    elif key == 'stroke':
                        styles['stroke'] = value
                    elif key == 'stroke-width':
                        styles['strokeWidth'] = float(value.replace('px', ''))
        
        return styles
    
    def _extract_edge_styles(self, element: ET.Element) -> Dict:
        """Extrait les styles d'une arête"""
        styles = {}
        
        stroke = element.get('stroke', 'black')
        styles['stroke'] = stroke
        
        stroke_width = element.get('stroke-width', '1')
        try:
            styles['strokeWidth'] = float(stroke_width)
        except ValueError:
            styles['strokeWidth'] = 1.0
        
        # Style de ligne (dashed, dotted, etc.)
        stroke_dasharray = element.get('stroke-dasharray')
        if stroke_dasharray:
            styles['dash'] = [float(x) for x in stroke_dasharray.split(',')]
        
        return styles
    
    def _extract_boundary_styles(self, element: ET.Element) -> Dict:
        """Extrait les styles d'une boundary"""
        styles = {}
        
        fill = element.get('fill', 'none')
        styles['fill'] = fill
        
        stroke = element.get('stroke', 'black')
        styles['stroke'] = stroke
        
        stroke_width = element.get('stroke-width', '1')
        try:
            styles['strokeWidth'] = float(stroke_width)
        except ValueError:
            styles['strokeWidth'] = 1.0
        
        # Style de ligne
        stroke_dasharray = element.get('stroke-dasharray')
        if stroke_dasharray:
            styles['dash'] = [float(x) for x in stroke_dasharray.split(',')]
        
        return styles
    
    def _determine_node_type(self, node_id: str, label: str) -> str:
        """Détermine le type de nœud à partir de l'ID et du label"""
        id_lower = node_id.lower()
        label_lower = label.lower()
        
        if 'actor' in id_lower or '👤' in label:
            return 'actor'
        elif 'database' in id_lower or '🗄️' in label:
            return 'database'
        elif 'firewall' in id_lower or '🔥' in label:
            return 'firewall'
        elif 'router' in id_lower or '🌐' in label:
            return 'router'
        elif 'switch' in id_lower or '🔀' in label:
            return 'switch'
        elif 'web' in id_lower:
            return 'web_server'
        elif 'api' in id_lower:
            return 'api_gateway'
        else:
            return 'server'
    
    def _extract_protocol(self, label: str, class_attr: str) -> str:
        """Extrait le protocole depuis le label ou les classes"""
        # Chercher dans le label
        protocol_match = re.search(r'Protocol:\s*(\w+)', label)
        if protocol_match:
            return protocol_match.group(1)
        
        # Chercher dans les classes
        classes = class_attr.split()
        for cls in classes:
            if cls.upper() in ['HTTP', 'HTTPS', 'SSH', 'FTP', 'TCP', 'UDP']:
                return cls.upper()
        
        return ''
    
    def save_metadata(self, metadata: Dict, output_path: Path) -> bool:
        """Sauvegarde les métadonnées au format JSON"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            logging.info(f"✅ Métadonnées sauvegardées: {output_path}")
            return True
            
        except Exception as e:
            logging.error(f"❌ Erreur sauvegarde métadonnées: {e}")
            return False


# Fonction d'intégration dans DiagramGenerator
def add_metadata_export_to_diagram_generator():
    """
    Code à ajouter dans la classe DiagramGenerator pour générer
    automatiquement les métadonnées lors de l'export SVG
    """
    
    code_snippet = '''
    def generate_diagram_with_metadata(self, threat_model, output_dir: Path, 
                                      project_protocol_styles: dict = None) -> Dict[str, Path]:
        """
        Génère le diagramme SVG et les métadonnées Konva associées
        
        Returns:
            Dict contenant les chemins: {'svg': Path, 'metadata': Path, 'html': Path}
        """
        from threat_analysis.generation.graphviz_to_konva import GraphvizToKonvaConverter
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        model_name = getattr(threat_model, 'name', 'diagram')
        safe_name = self._sanitize_name(model_name)
        
        # Générer le DOT
        dot_path = output_dir / f"{safe_name}.dot"
        dot_code = self.generate_dot_file_from_model(
            threat_model, 
            str(dot_path), 
            project_protocol_styles
        )
        
        if not dot_code:
            logging.error("Échec génération DOT")
            return {}
        
        # Générer le SVG
        svg_path = output_dir / f"{safe_name}.svg"
        svg_result = self.generate_diagram_from_dot(dot_code, str(svg_path), "svg")
        
        if not svg_result:
            logging.error("Échec génération SVG")
            return {}
        
        # Extraire et sauvegarder les métadonnées
        converter = GraphvizToKonvaConverter()
        metadata = converter.extract_metadata_from_svg(Path(svg_result))
        
        metadata_path = output_dir / f"{safe_name}_metadata.json"
        if metadata:
            converter.save_metadata(metadata, metadata_path)
        
        # Générer le HTML
        html_path = output_dir / f"{safe_name}.html"
        self._generate_html_with_legend(Path(svg_result), html_path, threat_model)
        
        return {
            'svg': Path(svg_result),
            'metadata': metadata_path if metadata else None,
            'html': html_path
        }
    '''
    
    return code_snippet
