using System;

namespace HotelReservationSystem.DTOs
{
    public class NewOrderDto
    {
        public int HotelId { get; set; }
        public string CustomerId { get; set; } = string.Empty;
        public DateTime OrderDate { get; set; }
        public DateTime CheckIn { get; set; }
        public DateTime CheckOut { get; set; }
        public int Days { get; set; }
        public decimal FullPrice { get; set; }
    }
}