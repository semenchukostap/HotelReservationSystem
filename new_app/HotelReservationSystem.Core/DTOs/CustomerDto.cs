using System;

namespace HotelReservationSystem.Core.DTOs
{
    public class CustomerDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public DateTime? Birthdate { get; set; }
    }
}