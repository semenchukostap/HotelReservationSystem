// Form validation module
const FormValidation = {
    init() {
        document.querySelectorAll('form[data-validate="true"]').forEach(form => {
            form.addEventListener('submit', this.handleSubmit);
        });
    },

    handleSubmit(event) {
        const form = event.currentTarget;
        if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }
        form.classList.add('was-validated');
    },

    resetForm(formElement) {
        formElement.classList.remove('was-validated');
        formElement.reset();
    }
};

// API service module
const ApiService = {
    async fetchData(url, options = {}) {
        try {
            const defaultOptions = {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin'
            };

            const response = await fetch(url, { ...defaultOptions, ...options });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const isJson = response.headers.get('content-type')?.includes('application/json');
            const data = isJson ? await response.json() : await response.text();
            
            return { success: true, data };
        } catch (error) {
            console.error('API Error:', error);
            return { success: false, error: error.message };
        }
    },

    async get(url) {
        return this.fetchData(url);
    },

    async post(url, data) {
        return this.fetchData(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    async put(url, data) {
        return this.fetchData(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    async delete(url) {
        return this.fetchData(url, {
            method: 'DELETE'
        });
    }
};

// Modal handler module
const ModalHandler = {
    init() {
        this.setupModalEvents();
    },

    setupModalEvents() {
        document.querySelectorAll('[data-bs-toggle="modal"]').forEach(button => {
            button.addEventListener('click', this.handleModalButton);
        });
    },

    async handleModalButton(event) {
        const button = event.currentTarget;
        const target = button.dataset.bsTarget;
        const url = button.dataset.url;

        if (url) {
            try {
                const { success, data } = await ApiService.get(url);
                if (success) {
                    const modal = document.querySelector(target);
                    modal.querySelector('.modal-content').innerHTML = data;
                }
            } catch (error) {
                console.error('Modal loading error:', error);
                showToast('Error loading modal content', 'error');
            }
        }
    }
};

// Toast notification module
const ToastNotification = {
    init() {
        this.container = document.getElementById('toast-container');
        if (!this.container) {
            this.createContainer();
        }
    },

    createContainer() {
        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        this.container.className = 'position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(this.container);
    },

    show(message, type = 'info') {
        const toastElement = document.createElement('div');
        toastElement.className = `toast align-items-center text-white bg-${type}`;
        toastElement.setAttribute('role', 'alert');
        toastElement.setAttribute('aria-live', 'assertive');
        toastElement.setAttribute('aria-atomic', 'true');

        toastElement.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        `;

        this.container.appendChild(toastElement);
        const toast = new bootstrap.Toast(toastElement);
        toast.show();

        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    }
};

// DataTable helper module
const DataTableHelper = {
    init(tableId, options = {}) {
        const defaultOptions = {
            responsive: true,
            language: {
                search: 'Search:',
                lengthMenu: 'Show _MENU_ entries',
                info: 'Showing _START_ to _END_ of _TOTAL_ entries',
                paginate: {
                    first: 'First',
                    last: 'Last',
                    next: 'Next',
                    previous: 'Previous'
                }
            }
        };

        return new DataTable(`#${tableId}`, { ...defaultOptions, ...options });
    }
};

// URL helper module
const UrlHelper = {
    getQueryParams() {
        return Object.fromEntries(new URLSearchParams(window.location.search));
    },

    updateQueryParam(key, value) {
        const params = new URLSearchParams(window.location.search);
        params.set(key, value);
        window.history.replaceState({}, '', `${window.location.pathname}?${params}`);
    }
};

// Document ready handler
document.addEventListener('DOMContentLoaded', () => {
    // Initialize modules
    FormValidation.init();
    ModalHandler.init();
    ToastNotification.init();

    // Setup global AJAX headers for CSRF protection
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (csrfToken) {
        document.addEventListener('fetch', (event) => {
            if (event.request.method !== 'GET') {
                event.request.headers.set('X-CSRF-TOKEN', csrfToken);
            }
        });
    }
});

// Export modules for use in other scripts
window.App = {
    ApiService,
    FormValidation,
    ModalHandler,
    ToastNotification,
    DataTableHelper,
    UrlHelper
};