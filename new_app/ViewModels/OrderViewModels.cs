using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for creating new orders, containing collections of customers and hotels for dropdown/selection
    /// </summary>
    public class NewOrderViewModel
    {
        /// <summary>
        /// Collection of customers for customer selection dropdown
        /// </summary>
        public IEnumerable<Customer> Customers { get; set; } = [];
        
        /// <summary>
        /// Collection of hotels for hotel selection dropdown
        /// </summary>
        public IEnumerable<Hotel> Hotels { get; set; } = [];
    }

    /// <summary>
    /// View model for displaying order details with complete information
    /// </summary>
    public class OrderDetailsViewModel
    {
        /// <summary>
        /// Gets or sets the unique identifier of the order
        /// </summary>
        public int OrderId { get; set; }

        /// <summary>
        /// Gets or sets the customer associated with the order
        /// </summary>
        public Customer? Customer { get; set; }

        /// <summary>
        /// Gets or sets the hotel associated with the order
        /// </summary>
        public Hotel? Hotel { get; set; }

        /// <summary>
        /// Gets or sets the check-in date
        /// </summary>
        public DateTime CheckInDate { get; set; }

        /// <summary>
        /// Gets or sets the check-out date
        /// </summary>
        public DateTime CheckOutDate { get; set; }

        /// <summary>
        /// Gets or sets the number of guests
        /// </summary>
        public int GuestCount { get; set; }

        /// <summary>
        /// Gets or sets the room type
        /// </summary>
        public string RoomType { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the total price of the order
        /// </summary>
        public decimal TotalPrice { get; set; }

        /// <summary>
        /// Gets or sets any special requests for the order
        /// </summary>
        public string SpecialRequests { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the booking confirmation number
        /// </summary>
        public string ConfirmationNumber { get; set; } = string.Empty;

        /// <summary>
        /// Gets the duration of the stay in days
        /// </summary>
        public int StayDuration => (CheckOutDate - CheckInDate).Days;

        /// <summary>
        /// Gets the formatted string representation of the total price
        /// </summary>
        public string FormattedPrice => $"${TotalPrice:F2}";

        /// <summary>
        /// Gets a value indicating whether the special requests field has content
        /// </summary>
        public bool HasSpecialRequests => !string.IsNullOrEmpty(SpecialRequests);
    }

    /// <summary>
    /// View model for displaying order summary information
    /// </summary>
    public class OrderSummaryViewModel
    {
        /// <summary>
        /// Gets or sets the unique identifier of the order
        /// </summary>
        public int OrderId { get; set; }

        /// <summary>
        /// Gets or sets the customer name
        /// </summary>
        public string CustomerName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the hotel name
        /// </summary>
        public string HotelName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the check-in date
        /// </summary>
        public DateTime CheckInDate { get; set; }

        /// <summary>
        /// Gets or sets the check-out date
        /// </summary>
        public DateTime CheckOutDate { get; set; }

        /// <summary>
        /// Gets or sets the total price of the order
        /// </summary>
        public decimal TotalPrice { get; set; }

        /// <summary>
        /// Gets or sets the booking status
        /// </summary>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// Gets the duration of the stay in days
        /// </summary>
        public int StayDuration => (CheckOutDate - CheckInDate).Days;

        /// <summary>
        /// Gets the formatted string representation of the total price
        /// </summary>
        public string FormattedPrice => $"${TotalPrice:F2}";

        /// <summary>
        /// Gets a value indicating whether the booking is currently active
        /// </summary>
        public bool IsActive => DateTime.Now < CheckOutDate && Status.Equals("Confirmed", StringComparison.OrdinalIgnoreCase);
    }
}