using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data Transfer Object for Order information
    /// </summary>
    public class OrderDto
    {
        /// <summary>
        /// Gets or sets the order identifier.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the customer identifier.
        /// </summary>
        public int CustomerId { get; set; }

        /// <summary>
        /// Gets or sets the customer name.
        /// </summary>
        public string CustomerName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the hotel identifier.
        /// </summary>
        public int HotelId { get; set; }

        /// <summary>
        /// Gets or sets the hotel name.
        /// </summary>
        public string HotelName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the date when the order was placed.
        /// </summary>
        [Required]
        public DateTime DateOrdered { get; set; }

        /// <summary>
        /// Gets or sets the start date of the stay.
        /// </summary>
        [Required]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// Gets or sets the end date of the stay.
        /// </summary>
        [Required]
        public DateTime EndDate { get; set; }

        /// <summary>
        /// Gets or sets the number of days.
        /// </summary>
        public int NumberOfDays { get; set; }

        /// <summary>
        /// Gets or sets the full price.
        /// </summary>
        public double FullPrice { get; set; }
    }
}