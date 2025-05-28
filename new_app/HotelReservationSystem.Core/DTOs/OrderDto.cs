using System;

namespace HotelReservationSystem.Core.DTOs
{
    public class OrderDto
    {
        public int Id { get; set; }
        public CustomerDto? Customer { get; set; }
        public HotelDto? Hotel { get; set; }
        public DateTime DateOrdered { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public int NumberOfDays { get; set; }
        public double FullPrice { get; set; }
    }
}