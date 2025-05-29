using System;
using System.ComponentModel.DataAnnotations;

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
        public int Id { get; set; }

        /// <summary>
        /// Customer's full name
        /// </summary>
        [Required]
        [MaxLength(255)]
        public string Name { get; set; }

        /// <summary>
        /// Customer's date of birth
        /// </summary>
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }

        /// <summary>
        /// Customer's email address
        /// </summary>
        [Required]
        [EmailAddress]
        [MaxLength(100)]
        public string Email { get; set; }

        /// <summary>
        /// Customer's phone number
        /// </summary>
        [Phone]
        [MaxLength(20)]
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Customer's address
        /// </summary>
        [MaxLength(500)]
        public string Address { get; set; }

        /// <summary>
        /// Customer loyalty program membership ID if enrolled
        /// </summary>
        [MaxLength(50)]
        public string LoyaltyMemberId { get; set; }

        /// <summary>
        /// Indicates if customer has subscribed to promotional emails
        /// </summary>
        public bool MarketingConsent { get; set; } = false;

        /// <summary>
        /// Date when the customer was registered in the system
        /// </summary>
        [DataType(DataType.DateTime)]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}