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

            toggle.addEventListener('click', () => {
                if (body.classList.contains('dark-mode')) {
                    localStorage.setItem('theme', 'light');
                    applyTheme('light');
                } else {
                    localStorage.setItem('theme', 'dark');
                    applyTheme('dark');
                }
            });

            // Apply theme on initial load
            const savedTheme = localStorage.getItem('theme') || 'light';
            applyTheme(savedTheme);
        }
    })();
});