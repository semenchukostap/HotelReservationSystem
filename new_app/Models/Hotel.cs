using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Hotel
    {
        public int Id { get; set; }

        [Required]
        [StringLength(255)]
        public string Name { get; set; } = string.Empty;

        [Required]
        public int CountryId { get; set; }

        public Country? Country { get; set; }

        [Required]
        [Range(1, 5)]
        public int Stars { get; set; }

        [Required]
        [Range(1, 10000)]
        public decimal Price { get; set; }
    }
}