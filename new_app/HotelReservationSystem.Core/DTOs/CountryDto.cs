using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.DTOs
{
    public class CountryDto
    {
        public int Id { get; set; }
        
        [Required]
        public string Name { get; set; } = string.Empty;
    }
}