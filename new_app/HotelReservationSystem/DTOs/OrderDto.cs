using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data transfer object for Order entity
    /// </summary>
    public class OrderDto
    {
        public int Id { get; set; }
        
        [Required]
        public CustomerDto Customer { get; set; }
        
        [Required]
        public int CustomerId { get; set; }
        
        [Required]
        public HotelDto Hotel { get; set; }
        
        [Required]
        public int HotelId { get; set; }

        [Required]
        public DateTime DateOrdered { get; set; }

        [Required]
        public DateTime StartDate { get; set; }

        [Required]
        public DateTime EndDate { get; set; }

        public int NumberOfDays { get; set; }

        public double FullPrice { get; set; }
    }
}