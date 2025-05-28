using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.Models
{
    public class Order
    {
        public int Id { get; set; }
        
        [Required]
        public int HotelId { get; set; }
        public Hotel? Hotel { get; set; }
        
        [Required]
        public string UserId { get; set; } = string.Empty;
        public ApplicationUser? User { get; set; }
        
        [Required]
        public DateTime ArrivalDate { get; set; }
        
        [Required]
        public DateTime DepartureDate { get; set; }
        
        [Required]
        [Range(1, 10)]
        public byte PeopleCount { get; set; }
        
        [Required]
        [Range(0, 100000)]
        public decimal FullPrice { get; set; }
    }
}