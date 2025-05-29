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
        public DateTime? Birthdate { get; set; }
    }
}