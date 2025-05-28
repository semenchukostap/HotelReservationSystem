// Common JavaScript functionality for the site

// Configure toastr notification defaults
$(document).ready(function () {
    toastr.options = {
        "closeButton": true,
        "debug": false,
        "newestOnTop": true,
        "progressBar": true,
        "positionClass": "toast-top-right",
        "preventDuplicates": false,
        "onclick": null,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "5000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    };
});

// Handle data-toggle="modal" elements to open modal dialogs
$(document).ready(function () {
    $('[data-toggle="modal"]').click(function (e) {
        e.preventDefault();
        var target = $(this).data('target');
        $(target).modal('show');
    });
});

// Global AJAX error handler
$(document).ajaxError(function (event, jqXHR, ajaxSettings, thrownError) {
    if (jqXHR.status === 401) {
        toastr.error("You need to be logged in to perform this action.", "Authentication Required");
    } else if (jqXHR.status === 403) {
        toastr.error("You don't have permission to perform this action.", "Access Denied");
    } else if (jqXHR.status >= 500) {
        toastr.error("A server error occurred. Please try again later.", "Server Error");
    }
});

// Initialize Bootstrap components
$(document).ready(function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
    const popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)
    });
});

// DataTables default configuration for Bootstrap 5
$(document).ready(function() {
    $.extend(true, $.fn.dataTable.defaults, {
        responsive: true,
        language: {
            search: "_INPUT_",
            searchPlaceholder: "Search...",
            lengthMenu: "_MENU_ records per page",
            info: "Showing _START_ to _END_ of _TOTAL_ entries",
            infoEmpty: "Showing 0 to 0 of 0 entries",
            infoFiltered: "(filtered from _MAX_ total entries)"
        },
        dom: "<'row'<'col-sm-12 col-md-6'l><'col-sm-12 col-md-6'f>>" +
             "<'row'<'col-sm-12'tr>>" +
             "<'row'<'col-sm-12 col-md-5'i><'col-sm-12 col-md-7'p>>",
        pageLength: 10,
        processing: true,
        stateSave: true,
        lengthMenu: [[5, 10, 25, 50, -1], [5, 10, 25, 50, "All"]],
        buttons: [
            'copy', 'excel', 'pdf', 'print'
        ]
    });
});

/**
 * Format a date string into a user-friendly format
 * @param {string|Date} dateString - The date to format (Date object or ISO string)
 * @param {string} format - Optional format (default: 'MM/DD/YYYY')
 * @returns {string} - Formatted date string
 */
function formatDate(dateString, format = 'MM/DD/YYYY') {
    if (!dateString) return '';
    
    const date = typeof dateString === 'string' ? new Date(dateString) : dateString;
    
    if (isNaN(date.getTime())) return 'Invalid date';
    
    // Format the date based on the requested format
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    
    switch (format.toUpperCase()) {
        case 'MM/DD/YYYY':
            return `${month}/${day}/${year}`;
        case 'DD/MM/YYYY':
            return `${day}/${month}/${year}`;
        case 'YYYY-MM-DD':
            return `${year}-${month}-${day}`;
        case 'MM/DD/YYYY HH:MM':
            return `${month}/${day}/${year} ${hours}:${minutes}`;
        default:
            return `${month}/${day}/${year}`;
    }
}

/**
 * Format a number as currency
 * @param {number} amount - The amount to format
 * @param {string} currencyCode - The currency code (default: 'USD')
 * @param {string} locale - The locale for formatting (default: 'en-US')
 * @returns {string} - Formatted currency string
 */
function formatCurrency(amount, currencyCode = 'USD', locale = 'en-US') {
    if (amount === null || amount === undefined) return '';
    
    try {
        return new Intl.NumberFormat(locale, {
            style: 'currency',
            currency: currencyCode,
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }).format(amount);
    } catch (error) {
        console.error('Currency formatting error:', error);
        return amount.toFixed(2);
    }
}

/**
 * Set active class for navigation menu based on current URL
 */
$(document).ready(function() {
    const currentPath = window.location.pathname;
    
    // Add 'active' class to nav links that match current path
    $('.navbar-nav .nav-link').each(function() {
        const linkPath = $(this).attr('href');
        
        if (linkPath && (currentPath === linkPath || 
           (linkPath !== '/' && currentPath.startsWith(linkPath)))) {
            $(this).addClass('active');
            
            // If inside a dropdown, also mark parent as active
            const dropdown = $(this).closest('.dropdown');
            if (dropdown.length) {
                dropdown.find('.dropdown-toggle').addClass('active');
            }
        }
    });
});