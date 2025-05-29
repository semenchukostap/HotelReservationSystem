using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data Transfer Object for updating an existing order
    /// </summary>
    public class UpdateOrderDto
    {
        /// <summary>
        /// The ID of the order to update
        /// </summary>
        [Required]
        public int Id { get; set; }

        /// <summary>
        /// The ID of the customer making the order
        /// </summary>
        [Required]
        public int CustomerId { get; set; }

        /// <summary>
        /// The ID of the hotel being ordered
        /// </summary>
        [Required]
        public int HotelId { get; set; }

        /// <summary>
        /// The starting date of the stay
        /// </summary>
        [Required]
        [DataType(DataType.Date)]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// The ending date of the stay
        /// </summary>
        [Required]
        [DataType(DataType.Date)]
        public DateTime EndDate { get; set; }
    }
}