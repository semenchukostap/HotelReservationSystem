using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data transfer object for Customer entity
    /// Contains essential customer information for API operations
    /// </summary>
    public class CustomerDto
    {
        /// <summary>
        /// Unique identifier for the customer
        /// </summary>
        [JsonPropertyName("id")]
        public int Id { get; set; }

        /// <summary>
        /// Customer's full name
        /// </summary>
        [Required(ErrorMessage = "Name is required")]
        [StringLength(255, ErrorMessage = "Name cannot exceed 255 characters")]
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Customer's date of birth
        /// </summary>
        [DataType(DataType.Date)]
        [JsonPropertyName("birthdate")]
        public DateTime? Birthdate { get; set; }
    }
}
