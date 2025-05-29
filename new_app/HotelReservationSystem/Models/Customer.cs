using System;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Text.Json.Serialization;

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
        /// Gets or sets the customer's name.
        /// </summary>
        [Required(ErrorMessage = "Name is required")]
        [MaxLength(255, ErrorMessage = "Name cannot exceed 255 characters")]
        [Display(Name = "Customer Name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the customer's birthdate.
        /// </summary>
        [Display(Name = "Date of Birth")]
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        public DateTime? Birthdate { get; set; }

        /// <summary>
        /// Navigation property for orders associated with this customer.
        /// </summary>
        [JsonIgnore]
        public virtual ICollection<Order>? Orders { get; set; }
    }
}