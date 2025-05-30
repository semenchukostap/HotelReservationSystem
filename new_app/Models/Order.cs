using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Order
    {
        public int Id { get; set; }

        public Customer? Customer { get; set; }
        
        [Required]
        public int CustomerId { get; set; }
        
        public Hotel? Hotel { get; set; }
        
        [Required]
        public int HotelId { get; set; }

        [Required]
        public DateTime DateCreated { get; set; }

        [Required]
        public DateTime CheckIn { get; set; }

        [Required]
        public DateTime CheckOut { get; set; }

        public double FullPrice { get; set; }
    }
}