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
class ExportManager {
    constructor(analysisResultContainer, threatModelJSON, convertJsonToMarkdown, uiManager) {
        this.analysisResultContainer = analysisResultContainer;
        this.threatModelJSON = threatModelJSON;
        this.convertJsonToMarkdown = convertJsonToMarkdown;
        this.uiManager = uiManager;
        this.exportMenu = null;
        this.exportButton = null;
    }

    initialize(exportButtonId, exportMenuId) {
        this.exportButton = document.getElementById(exportButtonId);
        this.exportMenu = document.getElementById(exportMenuId);

        if (!this.exportButton || !this.exportMenu) {
            console.error('ExportManager: Button or menu not found');
            return;
        }

        this.exportButton.addEventListener('click', (e) => this.toggleMenu(e));
        document.addEventListener('click', () => this.hideMenu());
        this.exportMenu.addEventListener('click', (e) => e.stopPropagation());
    }

    toggleMenu(e) {
        e.stopPropagation();
        this.exportMenu.style.display = this.exportMenu.style.display === 'block' ? 'none' : 'block';
    }

    hideMenu() {
        if (this.exportMenu) {
            this.exportMenu.style.display = 'none';
        }
    }

    exportModel(format) {
        this.hideMenu();

        if (this.uiManager) {
            this.uiManager.switchToTab('analysis');
        }

        const data = typeof this.threatModelJSON === 'function' ? this.threatModelJSON() : this.threatModelJSON;
        const markdown_content = this.convertJsonToMarkdown(data);

        this.analysisResultContainer.innerHTML = 
            '<div style="text-align: center; padding: 20px;">' +
                '<div class="loading-spinner"></div>' +
                '<br>Generating export...' +
            '</div>';

        fetch('/api/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ markdown: markdown_content, format: format })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Export failed');
            }

            const outputDir = response.headers.get('X-Output-Directory');

            return response.blob().then(blob => ({
                blob: blob,
                outputDir: outputDir,
                filename: this.getExportFilename(format)
            }));
        })
        .then(({ blob, outputDir, filename }) => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

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
        });
    }

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
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ExportManager;
}