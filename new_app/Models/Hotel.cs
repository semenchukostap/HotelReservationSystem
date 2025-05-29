using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Hotel
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public required string Name { get; set; }

    public Country? Country { get; set; }

    [Required]
    [Display(Name = "Country")]
    public int CountryId { get; set; }

    [Required]
    [MaxLength(50)]
    public required string City { get; set; }

    [Required]
    [Range(1, 5)]
    public int Stars { get; set; }

    [Required]
    [Range(1, 1000)]
    public double PricePerNight { get; set; }

    [Required]
    public bool IsAllInclusive { get; set; }
    
    public ICollection<Order>? Orders { get; set; }
}