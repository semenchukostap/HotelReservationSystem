namespace HotelReservationSystem.Models;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class Hotel
{
    [Key]
    public int Id { get; set; }

    [Required]
    [StringLength(100)]
    [Display(Name = "Hotel Name")]
    public required string Name { get; set; }

    [Required]
    [StringLength(200)]
    public required string Address { get; set; }

    [Required]
    [ForeignKey("Country")]
    [Display(Name = "Country")]
    public required int CountryId { get; set; }

    public virtual Country Country { get; set; } = null!;

    [Required]
    [Column(TypeName = "decimal(18,2)")]
    [Display(Name = "Price Per Night")]
    [Range(0, 999999.99)]
    public decimal PricePerNight { get; set; }

    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}