using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models;

/// <summary>
/// Represents a country in the system
/// </summary>
[Table("Countries")]
public class Country
{
    /// <summary>
    /// The unique identifier for the country
    /// </summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    
    /// <summary>
    /// The name of the country
    /// </summary>
    [Required(ErrorMessage = "Country name is required")]
    [StringLength(60, ErrorMessage = "Country name cannot exceed 60 characters")]
    [Display(Name = "Country Name")]
    public required string Name { get; set; } = string.Empty;
}