using System.ComponentModel.DataAnnotations;

namespace new_app.DTOs;

public class HotelDto
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    public string CountryName { get; set; } = string.Empty;

    [Required]
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
}