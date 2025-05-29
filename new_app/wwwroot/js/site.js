// Modern JavaScript Utilities
export class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

// Form validation module
export const FormValidation = {
    init() {
        document.addEventListener('submit', (event) => {
            if (event.target.matches('form[data-validate="true"]')) {
                this.handleSubmit(event);
            }
        });
    },

    handleSubmit(event) {
        const form = event.target;
        const isValid = this.validateForm(form);

        if (!isValid) {
            event.preventDefault();
            event.stopPropagation();
        }

        form.classList.add('was-validated');
    },

    validateForm(form) {
        const inputs = Array.from(form.elements);
        return inputs.every(input => this.validateInput(input));
    },

    validateInput(input) {
        if (!input.checkValidity()) {
            const errorMessage = input.validationMessage;
            ToastNotification.show(errorMessage, 'danger');
            return false;
        }
        return true;
    },

    resetForm(formElement) {
        if (!(formElement instanceof HTMLFormElement)) {
            throw new ValidationError('Invalid form element');
        }
        formElement.classList.remove('was-validated');
        formElement.reset();
    }
};

// API service module
export const ApiService = {
    async fetchData(url, options = {}) {
        try {
            const defaultOptions = {
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]')?.content
                },
                credentials: 'same-origin'
            };

            const response = await fetch(url, { ...defaultOptions, ...options });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const contentType = response.headers.get('content-type');
            const isJson = contentType?.includes('application/json');
            const data = isJson ? await response.json() : await response.text();
            
            return { success: true, data };
        } catch (error) {
            console.error('API Error:', error);
            ToastNotification.show(error.message, 'danger');
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
export const ModalHandler = {
    init() {
        document.addEventListener('click', (event) => {
            if (event.target.matches('[data-bs-toggle="modal"]')) {
                this.handleModalButton(event);
            }
        });
    },

    async handleModalButton(event) {
        const button = event.target;
        const target = button.dataset.bsTarget;
        const url = button.dataset.url;

        if (url) {
            try {
                const { success, data } = await ApiService.get(url);
                if (success && target) {
                    const modal = document.querySelector(target);
                    if (modal) {
                        const content = modal.querySelector('.modal-content');
                        if (content) {
                            content.innerHTML = data;
                            new bootstrap.Modal(modal).show();
                        }
                    }
                }
            } catch (error) {
                console.error('Modal loading error:', error);
                ToastNotification.show('Error loading modal content', 'danger');
            }
        }
    }
};

// Toast notification module
export const ToastNotification = {
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
        const toast = new bootstrap.Toast(toastElement, {
            animation: true,
            autohide: true,
            delay: 3000
        });
        toast.show();

        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    }
};

// DataTable helper module
export const DataTableHelper = {
    init(tableId, options = {}) {
        if (typeof tableId !== 'string') {
            throw new ValidationError('Table ID must be a string');
        }

        const defaultOptions = {
            responsive: true,
            dom: 'Bfrtip',
            buttons: ['copy', 'excel', 'pdf', 'print'],
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

        const table = document.getElementById(tableId);
        if (!table) {
            throw new ValidationError(`Table with ID "${tableId}" not found`);
        }

        return new DataTable(table, { ...defaultOptions, ...options });
    }
};

// URL helper module
export const UrlHelper = {
    getQueryParams() {
        return Object.fromEntries(new URLSearchParams(window.location.search));
    },

    updateQueryParam(key, value) {
        if (typeof key !== 'string') {
            throw new ValidationError('Query parameter key must be a string');
        }
        const params = new URLSearchParams(window.location.search);
        params.set(key, value);
        window.history.replaceState({}, '', `${window.location.pathname}?${params}`);
    },

    buildUrl(base, params = {}) {
        const url = new URL(base, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            url.searchParams.append(key, value);
        });
        return url.toString();
    }
};

// Document ready handler
document.addEventListener('DOMContentLoaded', () => {
    FormValidation.init();
    ModalHandler.init();
    ToastNotification.init();
});

// Export modules for legacy support
window.App = {
    ApiService,
    FormValidation,
    ModalHandler,
    ToastNotification,
    DataTableHelper,
    UrlHelper
};