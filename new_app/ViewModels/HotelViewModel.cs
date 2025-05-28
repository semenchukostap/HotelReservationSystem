using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels;

public class HotelViewModel
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    public IEnumerable<SelectListItem>? Countries { get; set; }

    [Required]
    [Display(Name = "Country")]
    public int CountryId { get; set; }

    [Required]
    [MaxLength(50)]
    public string City { get; set; } = string.Empty;

    [Required]
    [Range(1, 5)]
    public int Stars { get; set; }

    [Required]
    [Range(1, 1000)]
    public double PricePerNight { get; set; }

    [Required]
    public bool IsAllInclusive { get; set; }

    public string Title
    {
        get
        {
            return Id != 0 ? "Edit Hotel" : "New Hotel";
        }
    }

    public HotelViewModel()
    {
    }

    public HotelViewModel(Hotel hotel)
    {
        Id = hotel.Id;
        Name = hotel.Name;
        CountryId = hotel.CountryId;
        City = hotel.City;
        Stars = hotel.Stars;
        PricePerNight = hotel.PricePerNight;
        IsAllInclusive = hotel.IsAllInclusive;
    }
}