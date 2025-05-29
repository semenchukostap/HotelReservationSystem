using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models;

public class Hotel
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required(ErrorMessage = "Hotel name is required")]
    [StringLength(255, ErrorMessage = "Hotel name cannot exceed 255 characters")]
    [Display(Name = "Hotel Name")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "Country is required")]
    [Display(Name = "Country")]
    [ForeignKey(nameof(Country))]
    public int CountryId { get; set; }

    public Country? Country { get; set; }

    [Required(ErrorMessage = "City is required")]
    [StringLength(50, ErrorMessage = "City name cannot exceed 50 characters")]
    [Display(Name = "City")]
    public string City { get; set; } = string.Empty;

    [Required(ErrorMessage = "Star rating is required")]
    [Range(1, 5, ErrorMessage = "Star rating must be between 1 and 5")]
    [Display(Name = "Star Rating")]
    public int Stars { get; set; }

    [Required(ErrorMessage = "Price per night is required")]
    [Range(1, 10000, ErrorMessage = "Price must be between 1 and 10,000")]
    [Display(Name = "Price Per Night")]
    [Column(TypeName = "decimal(18,2)")]
    [DataType(DataType.Currency)]
    public decimal PricePerNight { get; set; }

    [Required(ErrorMessage = "All-inclusive status is required")]
    [Display(Name = "All Inclusive")]
    public bool IsAllInclusive { get; set; }

    // Navigation property for orders
    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}