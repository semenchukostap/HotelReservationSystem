using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data Transfer Object for Customer information
    /// </summary>
    public class CustomerDto
    {
        /// <summary>
        /// Gets or sets the customer identifier.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the customer name.
        /// </summary>
        [Required]
        [MaxLength(255)]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the customer birthdate.
        /// </summary>
        public DateTime? Birthdate { get; set; }
    }
}