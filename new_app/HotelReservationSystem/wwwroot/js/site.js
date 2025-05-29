// Main site JavaScript file that uses Bootstrap 5.3.2 components

// Enable tooltips and popovers (Bootstrap features)
document.addEventListener('DOMContentLoaded', () => {
    // Enable Bootstrap 5 tooltips everywhere
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Enable Bootstrap 5 popovers everywhere
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Configure toastr notification defaults
if (typeof toastr !== 'undefined') {
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
}

// DataTables default configuration
$(document).ready(function () {
    // Apply DataTables to tables with the 'datatable' class
    $('.datatable').each(function () {
        $(this).DataTable({
            responsive: true,
            language: {
                search: "_INPUT_",
                searchPlaceholder: "Search records"
            }
        });
    });

    // Handle Bootstrap modal events
    $('.modal').on('show.bs.modal', function (e) {
        // Additional custom code here
    });

    // Handle Bootstrap dropdown events
    $('.dropdown').on('show.bs.dropdown', function () {
        // Additional custom code here
    });

    // Handle confirmation dialogs using Bootbox
    $('.needs-confirmation').on('click', function (e) {
        e.preventDefault();
        const targetUrl = $(this).attr('href') || $(this).data('url');
        const message = $(this).data('confirm-message') || 'Are you sure you want to proceed?';
        
        bootbox.confirm({
            title: "Confirmation Required",
            message: message,
            buttons: {
                cancel: {
                    label: '<i class="fa fa-times"></i> Cancel',
                    className: 'btn-secondary'
                },
                confirm: {
                    label: '<i class="fa fa-check"></i> Confirm',
                    className: 'btn-primary'
                }
            },
            callback: function (result) {
                if (result) {
                    window.location.href = targetUrl;
                }
            }
        });
    });
});

// Handle form submissions with AJAX
function handleAjaxForm(formSelector, successCallback, errorCallback) {
    $(document).on('submit', formSelector, function (e) {
        e.preventDefault();
        
        const form = $(this);
        const url = form.attr('action');
        const method = form.attr('method') || 'POST';
        
        $.ajax({
            url: url,
            method: method,
            data: form.serialize(),
            success: function (response) {
                if (typeof successCallback === 'function') {
                    successCallback(response);
                } else {
                    // Default success handler
                    if (response.success) {
                        toastr.success(response.message || 'Operation completed successfully.');
                    } else {
                        toastr.error(response.message || 'There was an error processing your request.');
                    }
                }
            },
            error: function (xhr, status, error) {
                if (typeof errorCallback === 'function') {
                    errorCallback(xhr, status, error);
                } else {
                    // Default error handler
                    toastr.error('An error occurred: ' + error);
                }
            }
        });
    });
}