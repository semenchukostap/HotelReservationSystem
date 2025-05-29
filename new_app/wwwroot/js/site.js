// Site-wide JavaScript functionality
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Bootstrap components
    initBootstrapComponents();
    // Initialize custom functionality
    initCustomFunctionality();
});

// Bootstrap 5 component initializations
const initBootstrapComponents = () => {
    // Enable tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    [...tooltipTriggerList].map(el => new bootstrap.Tooltip(el));

    // Enable popovers
    const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]');
    [...popoverTriggerList].map(el => new bootstrap.Popover(el));

    // Auto-hide alerts after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.alert.alert-dismissible').forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
};

// Custom functionality initialization
const initCustomFunctionality = () => {
    handleFormValidation();
    initAjaxForms();
    initResponsiveTables();
    initBackToTop();
    highlightActiveNavigation();
    enhanceAccessibility();
    initConfirmDialogs();
};

// Form validation handling
const handleFormValidation = () => {
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
};

// AJAX form submission
const initAjaxForms = () => {
    document.querySelectorAll('form[data-ajax="true"]').forEach(form => {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            try {
                const formData = new FormData(form);
                const response = await fetch(form.action, {
                    method: form.method,
                    body: formData
                });
                const result = await response.json();
                handleAjaxResponse(result);
            } catch (error) {
                console.error('Form submission error:', error);
            }
        });
    });
};

// Responsive table handling
const initResponsiveTables = () => {
    document.querySelectorAll('.table-responsive').forEach(table => {
        const wrapper = document.createElement('div');
        wrapper.classList.add('table-wrapper');
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    });
};

// Back to top button functionality
const initBackToTop = () => {
    const backToTop = document.createElement('button');
    backToTop.innerHTML = '↑';
    backToTop.className = 'back-to-top btn btn-primary';
    document.body.appendChild(backToTop);

    window.addEventListener('scroll', () => {
        backToTop.classList.toggle('show', window.scrollY > 300);
    });

    backToTop.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
};

// Active navigation highlighting
const highlightActiveNavigation = () => {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
            link.setAttribute('aria-current', 'page');
        }
    });
};

// Accessibility improvements
const enhanceAccessibility = () => {
    // Add role attributes
    document.querySelectorAll('nav').forEach(nav => nav.setAttribute('role', 'navigation'));
    document.querySelectorAll('main').forEach(main => main.setAttribute('role', 'main'));
    
    // Add aria labels
    document.querySelectorAll('button:not([aria-label])').forEach(button => {
        if (!button.textContent.trim()) {
            button.setAttribute('aria-label', 'Button');
        }
    });
};

// Confirm dialog handler
const initConfirmDialogs = () => {
    document.querySelectorAll('[data-confirm]').forEach(element => {
        element.addEventListener('click', (event) => {
            if (!confirm(element.dataset.confirm)) {
                event.preventDefault();
                event.stopPropagation();
            }
        });
    });
};

// Helper function for AJAX responses
const handleAjaxResponse = (response) => {
    if (response.message) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${response.success ? 'success' : 'danger'} alert-dismissible fade show`;
        alert.innerHTML = `
            ${response.message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        document.querySelector('.container').insertAdjacentElement('afterbegin', alert);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    }
};