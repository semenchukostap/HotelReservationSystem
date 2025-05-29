using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class HotelDto
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public required string Name { get; set; }

        [Required]
        [StringLength(200)]
        public required string Address { get; set; }

        [Required]
        public int CountryId { get; set; }

        public string? CountryName { get; set; }
    }
}