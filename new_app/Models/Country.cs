using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a country entity in the hotel reservation system.
    /// </summary>
    public class Country
    {
        /// <summary>
        /// Gets or sets the unique identifier for the country.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the name of the country.
        /// Must not be empty and cannot exceed 255 characters.
        /// </summary>
        [Required(ErrorMessage = "Country name is required")]
        [StringLength(255, ErrorMessage = "Country name cannot exceed 255 characters")]
        [Display(Name = "Country Name")]
        public string Name { get; set; } = string.Empty;
    }
}