using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Web.Models;

public class Hotel
{
    public int Id { get; set; }

    [Required]
    [StringLength(255)]
    public string Name { get; set; } = null!;

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
    public decimal PricePerNight { get; set; }

    [Required]
    public bool IsAllInclusive { get; set; }

    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}