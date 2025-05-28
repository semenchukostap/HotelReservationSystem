using HotelReservationSystem.Models;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.ViewModels
{
    public class HotelViewModel
    {
        public int? Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string? Name { get; set; }

        [Display(Name = "Country")]
        [Required]
        public int? CountryId { get; set; }

        [Required]
        [MaxLength(50)]
        public string? City { get; set; }

        [Required]
        [Range(1, 5)]
        public int? Stars { get; set; }

        [Required]
        [Range(1, 1000)]
        [Display(Name = "Price Per Night")]
        public double? PricePerNight { get; set; }

        [Display(Name = "All Inclusive")]
        public bool IsAllInclusive { get; set; }

        public IEnumerable<SelectListItem>? Countries { get; set; }

        public string Title => Id.HasValue ? "Edit Hotel" : "New Hotel";
    }
}