using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data Transfer Object for creating a new hotel reservation order
    /// </summary>
    public class NewOrderDto
    {
        /// <summary>
        /// The ID of the customer making the reservation
        /// </summary>
        [Required(ErrorMessage = "Customer ID is required")]
        public int CustomerId { get; set; }

        /// <summary>
        /// The ID of the hotel being reserved
        /// </summary>
        [Required(ErrorMessage = "Hotel ID is required")]
        public int HotelId { get; set; }

        /// <summary>
        /// The start date of the reservation
        /// </summary>
        [Required(ErrorMessage = "Start date is required")]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// The end date of the reservation
        /// </summary>
        [Required(ErrorMessage = "End date is required")]
        [DataType(DataType.Date)]
        public DateTime EndDate { get; set; }

        /// <summary>
        /// The total number of days for the reservation
        /// This is calculated from StartDate and EndDate
        /// </summary>
        public int NumberOfDays { get; set; }
    }
}