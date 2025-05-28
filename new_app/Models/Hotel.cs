using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace HotelReservationSystem.Models
{
    public class Hotel
    {
        public int Id { get; set; }

        [Required]
        [StringLength(255)]
        public required string Name { get; set; }

        [ValidateNever]
        public Country? Country { get; set; }

        [Required]
        [Display(Name = "Country")]
        public int CountryId { get; set; }

        [Required]
        [StringLength(50)]
        public required string City { get; set; }

        [Required]
        [Range(1, 5)]
        public int Stars { get; set; }

        [Required]
        [Range(1, 1000)]
        [Display(Name = "Price Per Night")]
        public double PricePerNight { get; set; }

        [Required]
        [Display(Name = "All Inclusive")]
        public bool IsAllInclusive { get; set; }
    }
}