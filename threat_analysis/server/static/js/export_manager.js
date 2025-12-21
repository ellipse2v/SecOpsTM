/**
 * Export Manager - Module commun pour la gestion des exports
 * Peut être utilisé par les modes "gui" et "full-gui"
 */

class ExportManager {
    constructor(analysisResultContainer, threatModelJSON, convertJsonToMarkdown) {
        this.analysisResultContainer = analysisResultContainer;
        this.threatModelJSON = threatModelJSON;
        this.convertJsonToMarkdown = convertJsonToMarkdown;
        this.exportMenu = null;
        this.exportButton = null;
    }

    /**
     * Initialise le menu d'export
     * @param {string} exportButtonId - ID du bouton d'export
     * @param {string} exportMenuId - ID du menu d'export
     */
    initialize(exportButtonId, exportMenuId) {
        this.exportButton = document.getElementById(exportButtonId);
        this.exportMenu = document.getElementById(exportMenuId);

        if (!this.exportButton || !this.exportMenu) {
            console.error('ExportManager: Button or menu not found');
            return;
        }

        // Setup event listeners
        this.exportButton.addEventListener('click', (e) => this.toggleMenu(e));
        document.addEventListener('click', () => this.hideMenu());
        this.exportMenu.addEventListener('click', (e) => e.stopPropagation());

        // Setup export options
        this.setupExportOptions();
    }

    /**
     * Configure les options d'export dans le menu
     */
    setupExportOptions() {
        const exportOptions = [
            { format: 'svg', icon: '📊', name: 'SVG Diagram', description: 'Vector diagram for high-quality visualization' },
            { format: 'diagram', icon: '🖼️', name: 'HTML Diagram', description: 'HTML diagram with legend' },
            { format: 'report', icon: '📄', name: 'HTML Report', description: 'Complete report with STRIDE and MITRE analysis' },
            { format: 'json', icon: '📋', name: 'JSON Analysis', description: 'Structured JSON for programmatic processing' },
            { format: 'markdown', icon: '📝', name: 'Markdown', description: 'Markdown format for documentation' }
        ];

        this.exportMenu.innerHTML = '';
        exportOptions.forEach(option => {
            const optionElement = document.createElement('div');
            optionElement.className = 'export-option';
            optionElement.innerHTML = `${option.icon} ${option.name}`;
            optionElement.title = option.description;
            optionElement.onclick = () => this.exportModel(option.format);
            this.exportMenu.appendChild(optionElement);
        });
    }

    /**
     * Affiche/masque le menu d'export
     * @param {Event} e - Événement de clic
     */
    toggleMenu(e) {
        e.stopPropagation();
        this.exportMenu.style.display = this.exportMenu.style.display === 'block' ? 'none' : 'block';
    }

    /**
     * Masque le menu d'export
     */
    hideMenu() {
        if (this.exportMenu) {
            this.exportMenu.style.display = 'none';
        }
    }

    /**
     * Exporte le modèle dans le format spécifié
     * @param {string} format - Format d'export (svg, diagram, report, json, markdown)
     */
    exportModel(format) {
        this.hideMenu();

        // Get the current markdown content
        const markdown_content = this.convertJsonToMarkdown(this.threatModelJSON);

        // Show loading indicator
        this.analysisResultContainer.innerHTML = 
            '<div style="text-align: center; padding: 20px;">' +
                '<div class="loading-spinner"></div>' +
                '<br>Generating export...' +
            '</div>';

        // Send request to server
        fetch('/api/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ markdown: markdown_content, format: format })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Export failed');
            }

            // Get the output directory from headers
            const outputDir = response.headers.get('X-Output-Directory');

            return response.blob().then(blob => ({
                blob: blob,
                outputDir: outputDir,
                filename: this.getExportFilename(format)
            }));
        })
        .then(({ blob, outputDir, filename }) => {
            // Create download link
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            // Show success message with output directory
            this.analysisResultContainer.innerHTML = `
                <div style="text-align: center; padding: 20px; background-color: #e8f5e9; border-radius: 4px;">
                    <h3 style="color: #2e7d32; margin-bottom: 10px;">✅ Export Successful!</h3>
                    <p style="margin-bottom: 10px;">Your ${this.getExportFormatName(format)} has been downloaded.</p>
                    <p style="margin-bottom: 10px;">
                        <strong>📁 Saved in:</strong> <code>${outputDir}</code>
                    </p>
                    <p style="font-size: 14px; color: #666;">
                        All exports are saved in timestamped directories for easy organization.
                    </p>
                </div>
            `;

            // Restore the diagram after a short delay
            setTimeout(() => {
                if (typeof analyzeModel === 'function') {
                    analyzeModel();
                }
            }, 3000);
        })
        .catch(error => {
            console.error('Export error:', error);
            this.analysisResultContainer.innerHTML = `
                <div style="text-align: center; padding: 20px; background-color: #ffebee; border-radius: 4px;">
                    <h3 style="color: #c62828; margin-bottom: 10px;">❌ Export Failed</h3>
                    <p style="margin-bottom: 10px;">An error occurred while exporting.</p>
                    <p style="font-size: 14px; color: #666;">
                        Please try again or check the console for details.
                    </p>
                </div>
            `;

            // Restore the diagram after a short delay
            setTimeout(() => {
                if (typeof analyzeModel === 'function') {
                    analyzeModel();
                }
            }, 3000);
        });
    }

    /**
     * Génère un nom de fichier pour l'export
     * @param {string} format - Format d'export
     * @returns {string} Nom de fichier
     */
    getExportFilename(format) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const formatNames = {
            'svg': 'diagram',
            'diagram': 'diagram',
            'report': 'threat_model_report',
            'json': 'threat_analysis',
            'markdown': 'threat_model'
        };
        return `${formatNames[format] || 'export'}_${timestamp}.${format}`;
    }

    /**
     * Retourne le nom complet du format
     * @param {string} format - Format d'export
     * @returns {string} Nom complet du format
     */
    getExportFormatName(format) {
        const formatNames = {
            'svg': 'SVG diagram',
            'diagram': 'HTML diagram',
            'report': 'HTML report',
            'json': 'JSON analysis',
            'markdown': 'Markdown file'
        };
        return formatNames[format] || format;
    }

    /**
     * Crée le HTML pour le menu d'export
     * @returns {string} HTML du menu d'export
     */
    static getExportMenuHTML() {
        return `
        <div class="export-container">
            <button id="export-btn" class="export-btn">📥 Export</button>
            <div id="export-menu" class="export-menu"></div>
        </div>
        `;
    }

    /**
     * Crée le CSS pour le menu d'export
     * @returns {string} CSS du menu d'export
     */
    static getExportCSS() {
        return `
        /* Export menu styles */
        .export-container {
            position: relative;
            display: inline-block;
            margin-left: 10px;
        }

        .export-btn {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 16px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 4px;
            font-family: inherit;
        }

        .export-btn:hover {
            background-color: #45a049;
        }

        .export-menu {
            display: none;
            position: absolute;
            background-color: #f9f9f9;
            min-width: 200px;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
            z-index: 1;
            border-radius: 4px;
            overflow: hidden;
            right: 0;
        }

        .export-option {
            color: black;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.2s;
        }

        .export-option:hover {
            background-color: #e7f3ff;
        }

        .export-option:first-child {
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }

        .export-option:last-child {
            border-bottom-left-radius: 4px;
            border-bottom-right-radius: 4px;
        }

        /* Loading spinner for exports */
        .loading-spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-radius: 50%;
            border-top: 4px solid #4CAF50;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        `;
    }

    /**
     * Crée le CSS pour l'animation du spinner
     * @returns {string} CSS de l'animation
     */
    static getSpinnerAnimationCSS() {
        return `
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        `;
    }

    /**
     * Crée le JavaScript pour le menu d'export
     * @returns {string} JavaScript du menu d'export
     */
    static getExportJavascript() {
        return `
        // Export menu functionality
        const exportButton = document.getElementById('export-btn');
        const exportMenu = document.getElementById('export-menu');

        if (exportButton && exportMenu) {
            exportButton.addEventListener('click', function(e) {
                e.stopPropagation();
                exportMenu.style.display = exportMenu.style.display === 'block' ? 'none' : 'block';
            });

            document.addEventListener('click', function() {
                exportMenu.style.display = 'none';
            });

            exportMenu.addEventListener('click', function(e) {
                e.stopPropagation();
            });
        }
        `;
    }
}

// Export the class for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ExportManager;
}