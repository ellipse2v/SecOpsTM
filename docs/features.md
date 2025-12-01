# Features

- **Markdown-based Threat Modeling**: Use a simple DSL to describe your architecture and flows.
- **Automated STRIDE Analysis**: Detects threats for each element and flow.
- **MITRE ATT&CK Mapping**: Each threat is mapped to relevant MITRE tactics and techniques.
- **Severity Calculation**: Customizable scoring (base, target, protocol).
- **Comprehensive Reporting**:
  - HTML report with integrated threat statistics, detailed threat information, STRIDE/MITRE mapping, and D3FEND mitigations.
  - JSON export for integration or further analysis.
- **Visual Diagrams**:
  - DOT, SVG, and HTML diagrams with threat highlights.
- **Navigable Project Reports**:
  - Generate a unified, navigable HTML report for complex projects with multiple nested threat models.
  - Diagrams are interactive, with hover effects (zoom, shadow) on clickable elements.
  - Fully self-contained and works offline, with all necessary assets (like `svg-pan-zoom.js`) included locally.
- **Real-time Markdown Editing**: Edit your threat model in Markdown with live diagram preview.
- **Extensible**: All mappings and calculations are modular and easy to override.
- **PyTM Compatibility**: Supports PyTM's model structure and can be extended with PyTM's features.
