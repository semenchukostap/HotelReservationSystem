using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models;

public class Hotel
{
    public int Id { get; set; }

    [Required]
    [StringLength(255)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [Display(Name = "Country")]
    public int CountryId { get; set; }

    public Country? Country { get; set; }

    [Required]
    [StringLength(50)]
    public string City { get; set; } = string.Empty;

    [Required]
    [Range(1, 5)]
    [Display(Name = "Star Rating")]
    public int Stars { get; set; }

    [Required]
    [Range(1, 10000)]
    [Display(Name = "Price Per Night")]
    [Column(TypeName = "decimal(18,2)")]
    public decimal PricePerNight { get; set; }

    [Required]
    [Display(Name = "All Inclusive")]
    public bool IsAllInclusive { get; set; }

    // Navigation property for orders
    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}