using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Hotel
    {
        public int Id { get; set; }
        
        [Required]
        [StringLength(255)]
        public string Name { get; set; } = null!;
        
        [Required]
        [Display(Name = "Country")]
        public int CountryId { get; set; }
        
        public Country Country { get; set; } = null!;
        
        [Required]
        [StringLength(50)]
        public string City { get; set; } = null!;
        
        [Required]
        [Range(1, 5)]
        public int Stars { get; set; }
        
        [Required]
        [Range(1, 1000)]
        public double PricePerNight { get; set; }
        
        [Required]
        public bool IsAllInclusive { get; set; }
        
        public ICollection<Order> Orders { get; set; } = new List<Order>();
    }
}