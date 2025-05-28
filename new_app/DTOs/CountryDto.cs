namespace HotelReservationSystem.DTOs
{
    using System.ComponentModel.DataAnnotations;

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
        [Required]
        public required string Name { get; set; } = string.Empty;
        
        /// <summary>
        /// ISO code for the country
        /// </summary>
        [StringLength(2)]
        public string? IsoCode { get; set; }
    }
}
