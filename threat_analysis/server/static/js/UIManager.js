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
class UIManager {
    constructor(stage) {
        this.stage = stage;
        this.setupTabs();
        this.setupBackgroundColor();
    }

    setupTabs() {
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                this.switchToTab(button.dataset.tab);
            });
        });
    }

    switchToTab(tabId) {
        document.querySelectorAll('.tab-button, .tab-content').forEach(el => el.classList.remove('active'));
        const button = document.querySelector(`.tab-button[data-tab='${tabId}']`);
        if (button) {
            button.classList.add('active');
            const tabContent = document.getElementById(tabId);
            if (tabContent) {
                tabContent.classList.add('active');
            }
        }
    }

    setupBackgroundColor() {
        const graphBgColorInput = document.getElementById('graph-bg-color');
        if (graphBgColorInput) {
            graphBgColorInput.addEventListener('input', (event) => {
                this.stage.container().style.backgroundColor = event.target.value;
            });
        }
    }
}