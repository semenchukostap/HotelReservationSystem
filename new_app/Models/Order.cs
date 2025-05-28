using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel reservation order in the system.
    /// </summary>
    public class Order
    {
        /// <summary>
        /// Gets or sets the unique identifier for the order.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the customer who placed the order.
        /// </summary>
        [Required(ErrorMessage = "Customer information is required")]
        public required Customer Customer { get; set; }
        
        /// <summary>
        /// Gets or sets the hotel associated with this reservation.
        /// </summary>
        [Required(ErrorMessage = "Hotel information is required")]
        public required Hotel Hotel { get; set; }

        /// <summary>
        /// Gets or sets the date and time when the order was placed.
        /// </summary>
        [Required(ErrorMessage = "Order date is required")]
        [DataType(DataType.DateTime)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd HH:mm}", ApplyFormatInEditMode = true)]
        public DateTime DateOrdered { get; set; }

        /// <summary>
        /// Gets or sets the start date of the reservation.
        /// </summary>
        [Required(ErrorMessage = "Start date is required")]
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// Gets or sets the end date of the reservation.
        /// </summary>
        [Required(ErrorMessage = "End date is required")]
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        public DateTime EndDate { get; set; }

        /// <summary>
        /// Gets or sets the total number of days for the reservation.
        /// </summary>
        [Range(1, int.MaxValue, ErrorMessage = "Number of days must be at least 1")]
        public int NumberOfDays { get; set; }

        /// <summary>
        /// Gets or sets the full price of the reservation.
        /// </summary>
        [Range(0, double.MaxValue, ErrorMessage = "Price cannot be negative")]
        [DataType(DataType.Currency)]
        [Column(TypeName = "decimal(18, 2)")]
        public double FullPrice { get; set; }
    }
}