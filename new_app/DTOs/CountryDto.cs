using System;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data Transfer Object for Country entity
    /// </summary>
    public class CountryDto
    {
        /// <summary>
        /// Unique identifier for the country
        /// </summary>
        public int Id { get; set; }
        
        /// <summary>
        /// Name of the country
        /// </summary>
        public string Name { get; set; } = string.Empty;
    }
}