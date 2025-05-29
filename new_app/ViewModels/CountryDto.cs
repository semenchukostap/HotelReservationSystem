using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class CountryDto
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public required string Name { get; set; }
    }
}