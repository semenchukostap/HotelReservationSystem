// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Common JavaScript functions for the Hotel Reservation System

$(document).ready(function () {
    // Initialize DataTables where present
    if ($.fn.DataTable) {
        $('.table').DataTable({
            "pageLength": 10,
            "responsive": true
        });
    }

    // Set up AJAX token for POST requests
    $.ajaxSetup({
        headers: {
            'RequestVerificationToken': $('input:hidden[name="__RequestVerificationToken"]').val()
        }
    });

    // Configure toastr notifications
    if (typeof toastr !== 'undefined') {
        toastr.options = {
            "closeButton": true,
            "debug": false,
            "newestOnTop": true,
            "progressBar": true,
            "positionClass": "toast-top-right",
            "preventDuplicates": false,
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

    // Handle delete buttons with confirmation
    $(document).on("click", ".js-delete", function (e) {
        e.preventDefault();
        var button = $(this);
        var entityId = button.attr("data-entity-id");
        var entityType = button.attr("data-entity-type");

        bootbox.confirm({
            title: "Confirm Delete",
            message: "Are you sure you want to delete this " + entityType + "?",
            buttons: {
                cancel: {
                    label: '<i class="fa fa-times"></i> Cancel'
                },
                confirm: {
                    label: '<i class="fa fa-check"></i> Confirm'
                }
            },
            callback: function (result) {
                if (result) {
                    $.ajax({
                        url: "/api/" + entityType.toLowerCase() + "s/" + entityId,
                        method: "DELETE",
                        success: function () {
                            button.parents("tr").remove();
                            toastr.success(entityType + " deleted successfully.");
                        },
                        error: function (xhr) {
                            toastr.error("Failed to delete: " + xhr.responseText);
                        }
                    });
                }
            }
        });
    });
});