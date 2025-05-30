using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a country entity in the hotel reservation system.
    /// </summary>
    public class Country
    {
        public int Id { get; set; }

        [Required]
        [StringLength(255)]
        [Display(Name = "Country Name")]
        public string Name { get; set; } = string.Empty;
    }
}
