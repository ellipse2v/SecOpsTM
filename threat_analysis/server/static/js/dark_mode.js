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
document.addEventListener('DOMContentLoaded', () => {
    // Dark mode functionality
    (function() {
        const toggle = document.getElementById('darkModeToggle');
        const body = document.body;

        if (toggle) {
            const applyTheme = (theme) => {
                if (theme === 'dark') {
                    body.classList.add('dark-mode');
                } else {
                    body.classList.remove('dark-mode');
                }
            };

            const savedTheme = localStorage.getItem('theme') || 'light';
            applyTheme(savedTheme);


            document.addEventListener('DOMContentLoaded', () => {
            const toggle = document.getElementById('darkModeToggle');
            if (toggle) {
                toggle.addEventListener('click', () => {
                    if (document.body.classList.contains('dark-mode')) {
                        localStorage.setItem('theme', 'light');
                        applyTheme('light');
                    } else {
                        localStorage.setItem('theme', 'dark');
                        applyTheme('dark');
                    }
                });
        }
    });
        }
    })();
});