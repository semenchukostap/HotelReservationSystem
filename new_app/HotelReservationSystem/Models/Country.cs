using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a country entity in the system.
    /// Used for categorizing hotels by their geographical location.
    /// </summary>
    public class Country
    {
        /// <summary>
        /// Primary key identifier for the country
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Name of the country
        /// </summary>
        [Required(ErrorMessage = "Country name is required")]
        [MaxLength(255, ErrorMessage = "Country name cannot exceed 255 characters")]
        [Display(Name = "Country Name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Collection of hotels located in this country
        /// </summary>
        public virtual ICollection<Hotel>? Hotels { get; set; }
    }
}