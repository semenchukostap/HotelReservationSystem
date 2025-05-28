using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data Transfer Object for Country entity
    /// </summary>
    public class CountryDto
    {
        /// <summary>
        /// The unique identifier for the country
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// The name of the country
        /// </summary>
        [Required]
        public string Name { get; set; } = string.Empty;
    }
}