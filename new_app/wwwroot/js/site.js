/**
 * site.js - Client-side functionality for Hotel Reservation System
 * .NET 8 Migration
 */
$(document).ready(function () {
    // Initialize DataTables for all tables with the 'table' class
    $('.table').DataTable();
    
    // Delete hotel functionality
    $("#hotels").on("click", ".js-delete", function() {
        const button = $(this);
        
        bootbox.confirm({
            title: "Delete Hotel",
            message: "Are you sure you want to delete this hotel? This cannot be undone.",
            buttons: {
                cancel: {
                    label: '<i class="fa fa-times"></i> Cancel'
                },
                confirm: {
                    label: '<i class="fa fa-check"></i> Confirm'
                }
            },
            callback: function(result) {
                if (result) {
                    $.ajax({
                        url: `/api/hotels/${button.attr("data-hotel-id")}`,
                        method: "DELETE",
                        success: function() {
                            button.parents("tr").remove();
                            toastr.success("Hotel has been deleted successfully.");
                        },
                        error: function(xhr) {
                            toastr.error("Something went wrong! Could not delete hotel.");
                            console.error("Error:", xhr);
                        }
                    });
                }
            }
        });
    });
    
    // Delete customer functionality
    $("#customers").on("click", ".js-delete", function() {
        const button = $(this);
        
        bootbox.confirm({
            title: "Delete Customer",
            message: "Are you sure you want to delete this customer? This cannot be undone.",
            buttons: {
                cancel: {
                    label: '<i class="fa fa-times"></i> Cancel'
                },
                confirm: {
                    label: '<i class="fa fa-check"></i> Confirm'
                }
            },
            callback: function(result) {
                if (result) {
                    $.ajax({
                        url: `/api/customers/${button.attr("data-customer-id")}`,
                        method: "DELETE",
                        success: function() {
                            button.parents("tr").remove();
                            toastr.success("Customer has been deleted successfully.");
                        },
                        error: function(xhr) {
                            toastr.error("Something went wrong! Could not delete customer.");
                            console.error("Error:", xhr);
                        }
                    });
                }
            }
        });
    });
    
    // Delete order functionality
    $("#orders").on("click", ".js-delete", function() {
        const button = $(this);
        
        bootbox.confirm({
            title: "Delete Order",
            message: "Are you sure you want to delete this order? This cannot be undone.",
            buttons: {
                cancel: {
                    label: '<i class="fa fa-times"></i> Cancel'
                },
                confirm: {
                    label: '<i class="fa fa-check"></i> Confirm'
                }
            },
            callback: function(result) {
                if (result) {
                    $.ajax({
                        url: `/api/neworders/${button.attr("data-order-id")}`,
                        method: "DELETE",
                        success: function() {
                            button.parents("tr").remove();
                            toastr.success("Order has been deleted successfully.");
                        },
                        error: function(xhr) {
                            toastr.error("Something went wrong! Could not delete order.");
                            console.error("Error:", xhr);
                        }
                    });
                }
            }
        });
    });
    
    // New order functionality
    $("#newOrder").on("submit", function(e) {
        e.preventDefault();
        
        const customerId = $("#CustomerId").val();
        const hotelId = $("#HotelId").val();
        const startDate = $("#StartDate").val();
        const endDate = $("#EndDate").val();
        
        if (!customerId || !hotelId || !startDate || !endDate) {
            toastr.error("Please fill in all required fields!");
            return;
        }
        
        bootbox.confirm({
            title: "Create Order",
            message: "Are you sure you want to create this order?",
            buttons: {
                cancel: {
                    label: '<i class="fa fa-times"></i> Cancel'
                },
                confirm: {
                    label: '<i class="fa fa-check"></i> Confirm'
                }
            },
            callback: function(result) {
                if (result) {
                    const order = {
                        customerId: customerId,
                        hotelId: hotelId,
                        startDate: startDate,
                        endDate: endDate
                    };
                    
                    $.ajax({
                        url: "/api/neworders",
                        method: "POST",
                        contentType: "application/json",
                        data: JSON.stringify(order),
                        success: function(response) {
                            toastr.success("Order placed successfully!");
                            window.location.href = `/orders/details/${response.id}`;
                        },
                        error: function(xhr) {
                            if (xhr.responseJSON && xhr.responseJSON.message) {
                                toastr.error(xhr.responseJSON.message);
                            } else {
                                toastr.error("Something went wrong! Could not place order.");
                            }
                            console.error("Error:", xhr);
                        }
                    });
                }
            }
        });
    });
    
    // Typeahead for customers in the order form
    if ($("#customer").length) {
        const customers = new Bloodhound({
            datumTokenizer: Bloodhound.tokenizers.obj.whitespace('name'),
            queryTokenizer: Bloodhound.tokenizers.whitespace,
            remote: {
                url: '/api/customers?query=%QUERY',
                wildcard: '%QUERY'
            }
        });

        $("#customer").typeahead(
            {
                minLength: 1,
                highlight: true
            },
            {
                name: 'customers',
                display: 'name',
                source: customers
            }
        ).on("typeahead:select", function(e, customer) {
            window.viewModel = window.viewModel || {};
            window.viewModel.customerId = customer.id;
        });
    }
    
    // Typeahead for hotels in the order form
    if ($("#hotel").length) {
        const hotels = new Bloodhound({
            datumTokenizer: Bloodhound.tokenizers.obj.whitespace('name'),
            queryTokenizer: Bloodhound.tokenizers.whitespace,
            remote: {
                url: '/api/hotels?query=%QUERY',
                wildcard: '%QUERY'
            }
        });

        $("#hotel").typeahead(
            {
                minLength: 1,
                highlight: true
            },
            {
                name: 'hotels',
                display: 'name',
                source: hotels
            }
        ).on("typeahead:select", function(e, hotel) {
            window.viewModel = window.viewModel || {};
            window.viewModel.hotelId = hotel.id;
        });
    }
    
    // Date handling for orders
    $(document).on('change', "#StartDate", function() {
        window.viewModel = window.viewModel || {};
        window.viewModel.startDate = $(this).val();
    });

    $(document).on('change', "#EndDate", function() {
        window.viewModel = window.viewModel || {};
        window.viewModel.endDate = $(this).val();
    });
});