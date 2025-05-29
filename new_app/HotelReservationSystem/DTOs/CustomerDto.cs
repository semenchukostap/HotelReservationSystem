using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data transfer object for Customer entity
    /// Used for API operations and data exchange
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
        public string Name { get; set; } = null!;

        /// <summary>
        /// Customer's date of birth
        /// </summary>
        [DataType(DataType.Date)]
        [JsonPropertyName("birthdate")]
        public DateTime? Birthdate { get; set; }

        /// <summary>
        /// Customer's email address
        /// </summary>
        [Required(ErrorMessage = "Email address is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        [JsonPropertyName("email")]
        public string Email { get; set; } = null!;

        /// <summary>
        /// Customer's phone number
        /// </summary>
        [Phone(ErrorMessage = "Invalid phone number format")]
        [StringLength(20, ErrorMessage = "Phone number cannot exceed 20 characters")]
        [JsonPropertyName("phoneNumber")]
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Customer's address
        /// </summary>
        [StringLength(500, ErrorMessage = "Address cannot exceed 500 characters")]
        [JsonPropertyName("address")]
        public string? Address { get; set; }

        /// <summary>
        /// Customer loyalty program membership ID if enrolled
        /// </summary>
        [StringLength(50, ErrorMessage = "Loyalty member ID cannot exceed 50 characters")]
        [JsonPropertyName("loyaltyMemberId")]
        public string? LoyaltyMemberId { get; set; }

        /// <summary>
        /// Indicates if customer has subscribed to promotional emails
        /// </summary>
        [JsonPropertyName("marketingConsent")]
        public bool MarketingConsent { get; set; } = false;

        /// <summary>
        /// Date when the customer was registered in the system
        /// </summary>
        [DataType(DataType.DateTime)]
        [JsonPropertyName("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
