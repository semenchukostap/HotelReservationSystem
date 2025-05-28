using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Collections.Generic;

namespace HotelReservationSystem.Models;

public class Hotel
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    [Display(Name = "Hotel Name")]
    public string Name { get; set; } = string.Empty;

    [ForeignKey("CountryId")]
    public Country? Country { get; set; }

    [Required]
    [Display(Name = "Country")]
    public int CountryId { get; set; }

    [Required]
    [MaxLength(50)]
    [Display(Name = "City")]
    public string City { get; set; } = string.Empty;

    [Required]
    [Range(1, 5)]
    [Display(Name = "Star Rating")]
    public int Stars { get; set; }

    [Required]
    [Range(1, 1000)]
    [Display(Name = "Price Per Night")]
    [DataType(DataType.Currency)]
    [Column(TypeName = "decimal(18, 2)")]
    public decimal PricePerNight { get; set; }

    [Required]
    [Display(Name = "All Inclusive")]
    public bool IsAllInclusive { get; set; }

    [MaxLength(500)]
    [Display(Name = "Description")]
    public string? Description { get; set; }

    [Display(Name = "Available Rooms")]
    [Range(0, 1000)]
    public int AvailableRooms { get; set; }

    // Navigation properties
    public virtual ICollection<Reservation>? Reservations { get; set; }
    
    [NotMapped]
    public bool IsAvailable => AvailableRooms > 0;
}