// Site-wide JavaScript functionality

// Configure toastr notifications
$(function () {
    toastr.options = {
        "closeButton": true,
        "positionClass": "toast-top-right",
        "timeOut": "3000"
    };
});

// Common DataTables configuration
function configureDataTable(tableSelector) {
    $(tableSelector).DataTable({
        "responsive": true,
        "pagingType": "full_numbers",
        "lengthMenu": [[10, 25, 50, -1], [10, 25, 50, "All"]]
    });
}

// Generic delete confirmation
function confirmDelete(url, name, callback) {
    bootbox.confirm({
        title: "Delete Confirmation",
        message: "Are you sure you want to delete " + name + "?",
        buttons: {
            cancel: {
                label: '<i class="fa fa-times"></i> Cancel'
            },
            confirm: {
                label: '<i class="fa fa-check"></i> Delete'
            }
        },
        callback: function (result) {
            if (result) {
                $.ajax({
                    url: url,
                    method: "DELETE",
                    success: function () {
                        toastr.success("Successfully deleted " + name);
                        if (typeof callback === 'function') {
                            callback();
                        }
                    },
                    error: function (jqXHR) {
                        toastr.error("Error deleting record: " + jqXHR.responseText);
                    }
                });
            }
        }
    });
}