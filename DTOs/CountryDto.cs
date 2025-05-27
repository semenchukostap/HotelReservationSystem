using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    public class CountryDto
    {
        public int Id { get; set; }

        [Required]
        public string Name { get; set; }
    }
}