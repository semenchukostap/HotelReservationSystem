using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Country
    {
        public int Id { get; set; }
        
        [Required]
        public required string Name { get; set; } = string.Empty;
    }
}
