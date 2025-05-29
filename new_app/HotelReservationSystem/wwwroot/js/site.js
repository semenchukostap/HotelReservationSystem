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

    // Apply custom DataTables to reservation tables
    $('#reservationsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']],
        columnDefs: [
            { type: 'date', targets: [1, 2] }
        ],
        dom: 'Bfrtip',
        buttons: [
            'copy', 'excel', 'pdf', 'print'
        ]
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

    // Initialize date range picker for reservation forms
    if (typeof daterangepicker !== 'undefined') {
        $('#reservationDateRange').daterangepicker({
            opens: 'left',
            locale: {
                format: 'MM/DD/YYYY',
                separator: ' - '
            },
            minDate: moment()
        });
    }

    // Initialize Typeahead for guest search
    if (typeof Bloodhound !== 'undefined') {
        var guests = new Bloodhound({
            datumTokenizer: Bloodhound.tokenizers.obj.whitespace('value'),
            queryTokenizer: Bloodhound.tokenizers.whitespace,
            remote: {
                url: '/api/guests/search?q=%QUERY',
                wildcard: '%QUERY'
            }
        });

        $('#guestSearch').typeahead(null, {
            name: 'guests',
            display: 'name',
            source: guests,
            templates: {
                suggestion: function(data) {
                    return '<div>' + data.name + ' - ' + data.email + '</div>';
                }
            }
        }).on('typeahead:selected', function(e, suggestion) {
            $('#guestId').val(suggestion.id);
        });
    }

    // Initialize form validation
    if (typeof $.validator !== 'undefined') {
        $.validator.setDefaults({
            errorElement: 'span',
            errorPlacement: function (error, element) {
                error.addClass('invalid-feedback');
                element.closest('.form-group').append(error);
            },
            highlight: function (element, errorClass, validClass) {
                $(element).addClass('is-invalid');
            },
            unhighlight: function (element, errorClass, validClass) {
                $(element).removeClass('is-invalid');
            }
        });

        // Reservation form validation
        $("#reservationForm").validate({
            rules: {
                guestName: "required",
                email: {
                    required: true,
                    email: true
                },
                phone: "required",
                roomType: "required",
                guests: {
                    required: true,
                    digits: true,
                    min: 1
                }
            }
        });
    }
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

// Room availability checking
function checkRoomAvailability(startDate, endDate, roomType, callback) {
    $.ajax({
        url: '/api/rooms/checkAvailability',
        method: 'GET',
        data: {
            startDate: startDate,
            endDate: endDate,
            roomType: roomType
        },
        success: function(response) {
            if (typeof callback === 'function') {
                callback(response);
            } else {
                if (response.available) {
                    toastr.success('Rooms available for the selected dates.');
                } else {
                    toastr.warning('No rooms available for the selected dates.');
                }
            }
        },
        error: function() {
            toastr.error('Error checking room availability.');
        }
    });
}

// Calculate reservation cost
function calculateReservationCost() {
    const roomType = $('#roomType').val();
    const dateRange = $('#reservationDateRange').val();
    const guests = $('#guests').val();
    
    if (roomType && dateRange && guests) {
        const dates = dateRange.split(' - ');
        if (dates.length === 2) {
            $.ajax({
                url: '/api/reservations/calculateCost',
                method: 'GET',
                data: {
                    roomType: roomType,
                    startDate: dates[0],
                    endDate: dates[1],
                    guests: guests
                },
                success: function(response) {
                    $('#totalCost').val(response.totalCost);
                    $('#costBreakdown').html(response.breakdown);
                },
                error: function() {
                    toastr.error('Error calculating reservation cost.');
                }
            });
        }
    }
}

// Create a reservation
function createReservation(formData, successCallback, errorCallback) {
    $.ajax({
        url: '/api/reservations',
        method: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            if (typeof successCallback === 'function') {
                successCallback(response);
            } else {
                toastr.success('Reservation created successfully!');
                setTimeout(() => window.location.href = '/reservations', 1500);
            }
        },
        error: function(xhr) {
            if (typeof errorCallback === 'function') {
                errorCallback(xhr);
            } else {
                toastr.error('Failed to create reservation.');
            }
        }
    });
}