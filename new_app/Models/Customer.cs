using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a customer in the hotel reservation system.
    /// </summary>
    public class Customer
    {
        /// <summary>
        /// Gets or sets the unique identifier for the customer.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the name of the customer.
        /// </summary>
        [Required]
        [MaxLength(255)]
        [Display(Name = "Customer Name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the birthdate of the customer.
        /// </summary>
        [Display(Name = "Date of Birth")]
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }
    }
}