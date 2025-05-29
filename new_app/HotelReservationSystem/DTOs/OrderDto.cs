using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data transfer object for Order entity.
    /// Represents a reservation order in the hotel reservation system.
    /// </summary>
    public class OrderDto
    {
        /// <summary>
        /// Gets or sets the unique identifier for the order.
        /// </summary>
        [JsonPropertyName("id")]
        public int Id { get; set; }
        
        /// <summary>
        /// Gets or sets the customer information associated with the order.
        /// </summary>
        [Required]
        [JsonPropertyName("customer")]
        public CustomerDto? Customer { get; set; }
        
        /// <summary>
        /// Gets or sets the customer identifier.
        /// </summary>
        [Required]
        [JsonPropertyName("customerId")]
        public int CustomerId { get; set; }
        
        /// <summary>
        /// Gets or sets the hotel information associated with the order.
        /// </summary>
        [Required]
        [JsonPropertyName("hotel")]
        public HotelDto? Hotel { get; set; }
        
        /// <summary>
        /// Gets or sets the hotel identifier.
        /// </summary>
        [Required]
        [JsonPropertyName("hotelId")]
        public int HotelId { get; set; }

        /// <summary>
        /// Gets or sets the date when the order was placed.
        /// </summary>
        [Required]
        [JsonPropertyName("dateOrdered")]
        public DateTime DateOrdered { get; set; }

        /// <summary>
        /// Gets or sets the start date of the reservation.
        /// </summary>
        [Required]
        [JsonPropertyName("startDate")]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// Gets or sets the end date of the reservation.
        /// </summary>
        [Required]
        [JsonPropertyName("endDate")]
        public DateTime EndDate { get; set; }

        /// <summary>
        /// Gets or sets the total number of days for the reservation.
        /// </summary>
        [JsonPropertyName("numberOfDays")]
        public int NumberOfDays { get; set; }

        /// <summary>
        /// Gets or sets the full price of the reservation.
        /// </summary>
        [JsonPropertyName("fullPrice")]
        public double FullPrice { get; set; }
    }
}
