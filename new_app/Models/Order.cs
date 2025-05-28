using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel reservation order in the system
    /// </summary>
    public class Order
    {
        /// <summary>
        /// The unique identifier for the order
        /// </summary>
        [Key]
        public int Id { get; set; }

        /// <summary>
        /// The customer who placed the order
        /// </summary>
        [Required]
        [ValidateNever]
        [ForeignKey("CustomerId")]
        public Customer Customer { get; set; } = null!;

        /// <summary>
        /// Foreign key for Customer
        /// </summary>
        public int CustomerId { get; set; }
        
        /// <summary>
        /// The hotel being reserved
        /// </summary>
        [Required]
        [ValidateNever]
        [ForeignKey("HotelId")]
        public Hotel Hotel { get; set; } = null!;

        /// <summary>
        /// Foreign key for Hotel
        /// </summary>
        public int HotelId { get; set; }

        /// <summary>
        /// The date when the order was placed
        /// </summary>
        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Order Date")]
        public DateTime DateOrdered { get; set; }

        /// <summary>
        /// The check-in date for the reservation
        /// </summary>
        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Check-in Date")]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// The check-out date for the reservation
        /// </summary>
        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Check-out Date")]
        public DateTime EndDate { get; set; }

        /// <summary>
        /// The total number of days for the stay
        /// </summary>
        [Display(Name = "Number of Days")]
        [Range(1, 365)]
        public int NumberOfDays { get; set; }

        /// <summary>
        /// The total price for the reservation
        /// </summary>
        [Display(Name = "Total Price")]
        [DataType(DataType.Currency)]
        [Column(TypeName = "decimal(18, 2)")]
        public decimal FullPrice { get; set; }
    }
}