/**
 * DataTables initialization helper functions for Hotel Reservation System
 * This file provides reusable functions for initializing DataTables across the application
 */

// Initialize basic DataTable
function initDataTable(tableId) {
    $(tableId).DataTable({
        language: {
            emptyTable: "No records found"
        }
    });
}

// Initialize DataTable with AJAX source
function initDataTableAjax(tableId, url, columns, columnDefs = []) {
    return $(tableId).DataTable({
        ajax: {
            url: url,
            dataSrc: ""
        },
        columns: columns,
        columnDefs: columnDefs,
        language: {
            emptyTable: "No records found"
        },
        processing: true,
        responsive: true
    });
}

// Initialize Hotels DataTable
function initHotelsDataTable(tableId) {
    return initDataTableAjax(
        tableId,
        "/api/hotels",
        [
            { data: "name" },
            { data: "address" },
            { data: "country.name" },
            {
                data: "id",
                render: function (data, type, hotel) {
                    if (hotel.canEdit) {
                        return `
                            <a href="/Hotels/Edit/${data}" class="btn btn-link">Edit</a> | 
                            <button data-id="${data}" class="btn btn-link text-danger js-delete">Delete</button>
                        `;
                    }
                    return `<a href="/Hotels/Details/${data}" class="btn btn-link">Details</a>`;
                },
                orderable: false
            }
        ]
    );
}

// Initialize Customers DataTable
function initCustomersDataTable(tableId) {
    return initDataTableAjax(
        tableId,
        "/api/customers",
        [
            { data: "name" },
            { data: "phone" },
            {
                data: "id",
                render: function (data) {
                    return `
                        <a href="/Customers/Edit/${data}" class="btn btn-link">Edit</a> | 
                        <button data-id="${data}" class="btn btn-link text-danger js-delete">Delete</button>
                    `;
                },
                orderable: false
            }
        ]
    );
}

// Initialize Orders DataTable
function initOrdersDataTable(tableId) {
    return initDataTableAjax(
        tableId,
        "/api/orders",
        [
            { 
                data: "customer.name",
                render: function(data, type, order) {
                    return `<a href="/Customers/Details/${order.customer.id}">${data}</a>`;
                }
            },
            { 
                data: "hotel.name",
                render: function(data, type, order) {
                    return `<a href="/Hotels/Details/${order.hotel.id}">${data}</a>`;
                }
            },
            { 
                data: "dateCreated",
                render: function (data) {
                    return new Date(data).toLocaleDateString();
                }
            },
            {
                data: "id",
                render: function (data) {
                    return `<a href="/Orders/Details/${data}" class="btn btn-link">Details</a>`;
                },
                orderable: false
            }
        ]
    );
}

// Handle delete operations for DataTables
function handleDataTableDelete(table, url) {
    $(document).on("click", ".js-delete", function () {
        const button = $(this);
        bootbox.confirm({
            message: "Are you sure you want to delete this record?",
            buttons: {
                confirm: {
                    label: "Yes",
                    className: "btn-danger"
                },
                cancel: {
                    label: "No",
                    className: "btn-secondary"
                }
            },
            callback: function (result) {
                if (result) {
                    $.ajax({
                        url: url + "/" + button.data("id"),
                        method: "DELETE",
                        success: function () {
                            table.row(button.parents("tr")).remove().draw();
                            toastr.success("Record has been deleted");
                        },
                        error: function () {
                            toastr.error("Error deleting record");
                        }
                    });
                }
            }
        });
    });
}