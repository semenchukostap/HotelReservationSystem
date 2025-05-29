using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class OrderDto
    {
        public int Id { get; set; }

        [Required]
        public required string CustomerId { get; set; }

        [Required]
        public int HotelId { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime CheckInDate { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime CheckOutDate { get; set; }

        [Required]
        [DataType(DataType.Currency)]
        public decimal FullPrice { get; set; }

        public string? CustomerName { get; set; }
        public string? HotelName { get; set; }
    }
}