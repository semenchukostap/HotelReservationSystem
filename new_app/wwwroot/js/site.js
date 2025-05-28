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