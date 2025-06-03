using System.ComponentModel.DataAnnotations;

namespace new_app.ViewModels
{
    public class HotelViewModel
    {
        public int? Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string Name { get; set; }

        [Required]
        [Display(Name = "Country")]
        public int CountryId { get; set; }

        [Required]
        [MaxLength(50)]
        public string City { get; set; }

        [Required]
        [Range(1, 5)]
        public int Stars { get; set; }

        [Required]
        [Range(1, 1000)]
        public double PricePerNight { get; set; }

        [Required]
        public bool IsAllInclusive { get; set; }
    }
}