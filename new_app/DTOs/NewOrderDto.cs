using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    public class NewOrderDto
    {
        [Required]
        public int CustomerId { get; set; }

        [Required]
        public int HotelId { get; set; }

        [Required]
        public DateTime CheckIn { get; set; }

        [Required]
        public DateTime CheckOut { get; set; }
    }
}