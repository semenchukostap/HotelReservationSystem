using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Order
    {
        public int Id { get; set; }
        
        [Required]
        public Hotel? Hotel { get; set; }
        
        public int HotelId { get; set; }
        
        [Required]
        public string CustomerId { get; set; } = string.Empty;
        
        public ApplicationUser? Customer { get; set; }
        
        [Required]
        public DateTime OrderDate { get; set; }
        
        [Required]
        public DateTime CheckIn { get; set; }
        
        [Required]
        public DateTime CheckOut { get; set; }
        
        [Required]
        public int Days { get; set; }
        
        [Required]
        public decimal FullPrice { get; set; }
    }
}