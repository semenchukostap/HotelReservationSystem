// Common JavaScript functions for the site

// Configure toastr options
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

// Helper function to format dates consistently
function formatDate(date) {
    if (!date) return '';
    if (typeof date === 'string') {
        date = new Date(date);
    }
    return new Intl.DateTimeFormat('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: '2-digit' 
    }).format(date);
}

// Helper function to format currency values
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

// Add CSRF token to AJAX requests
$(function () {
    // Get the anti-forgery token
    const token = $('input[name="__RequestVerificationToken"]').val();
    
    // Add the token to all AJAX requests
    $.ajaxSetup({
        headers: {
            'RequestVerificationToken': token
        }
    });
});