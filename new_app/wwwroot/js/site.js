// Site-wide JavaScript functionality
const SiteModule = {
    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.initializeBootstrapComponents();
            this.setupAlertHandling();
            this.initializeDataTables();
        });
    },

    initializeBootstrapComponents() {
        // Enable tooltips everywhere
        const tooltipTriggerList = [...document.querySelectorAll('[data-bs-toggle="tooltip"]')];
        tooltipTriggerList.forEach(el => new bootstrap.Tooltip(el));

        // Enable popovers everywhere
        const popoverTriggerList = [...document.querySelectorAll('[data-bs-toggle="popover"]')];
        popoverTriggerList.forEach(el => new bootstrap.Popover(el));
    },

    setupAlertHandling() {
        // Auto-hide alerts after 5 seconds
        setTimeout(() => {
            document.querySelectorAll('.alert.alert-dismissible').forEach(alert => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            });
        }, 5000);
    },

    initializeDataTables() {
        // Initialize DataTables with default configuration
        const tables = document.querySelectorAll('.datatable');
        tables.forEach(table => {
            new DataTable(table, {
                responsive: true,
                language: {
                    search: "Search:",
                    lengthMenu: "Show _MENU_ entries per page",
                    info: "Showing _START_ to _END_ of _TOTAL_ entries",
                    paginate: {
                        first: "First",
                        last: "Last",
                        next: "Next",
                        previous: "Previous"
                    }
                }
            });
        });
    },

    async fetchData(url, options = {}) {
        try {
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    }
};

// Initialize the site module
SiteModule.init();

// Export module for use in other files if needed
export default SiteModule;
