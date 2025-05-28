using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.DTOs
{
    public class HotelDto
    {
        public int Id { get; set; }
        
        [Required]
        [StringLength(255)]
        public string Name { get; set; } = string.Empty;
        
        [Required]
        [StringLength(255)]
        public string City { get; set; } = string.Empty;
        
        [Required]
        public int CountryId { get; set; }
        
        public string? CountryName { get; set; }
        
        [Range(1, 5)]
        public byte Stars { get; set; }
        
        public bool IsAllInclusive { get; set; }
        
        [Required]
        [Range(0, 10000)]
        public decimal PricePerNight { get; set; }
    }
}