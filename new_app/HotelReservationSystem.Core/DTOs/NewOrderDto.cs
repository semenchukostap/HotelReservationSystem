using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.DTOs
{
    public class NewOrderDto
    {
        [Required]
        public int HotelId { get; set; }
        
        [Required]
        public string UserId { get; set; } = string.Empty;
        
        [Required]
        public DateTime ArrivalDate { get; set; }
        
        [Required]
        public DateTime DepartureDate { get; set; }
        
        [Required]
        [Range(1, 10)]
        public byte PeopleCount { get; set; }
    }
}