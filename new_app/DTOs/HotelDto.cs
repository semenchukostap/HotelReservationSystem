using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs;

/// <summary>
/// Data Transfer Object for Hotel entity
/// </summary>
public class HotelDto
{
    /// <summary>
    /// Unique identifier for the hotel
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Name of the hotel
    /// </summary>
    [Required]
    [MaxLength(255)]
    public required string Name { get; set; } = string.Empty;

    /// <summary>
    /// Foreign key to the country where the hotel is located
    /// </summary>
    [Required]
    public required int CountryId { get; set; }

    /// <summary>
    /// Navigation property to the country
    /// </summary>
    public CountryDto? Country { get; set; }

    /// <summary>
    /// City where the hotel is located
    /// </summary>
    [Required]
    [MaxLength(50)]
    public required string City { get; set; } = string.Empty;

    /// <summary>
    /// Hotel quality rating (1-5 stars)
    /// </summary>
    [Required]
    [Range(1, 5)]
    public required int Stars { get; set; }

    /// <summary>
    /// Base price per night in the hotel
    /// </summary>
    [Required]
    [Range(1, 1000)]
    public required double PricePerNight { get; set; }

    /// <summary>
    /// Indicates whether the hotel offers all-inclusive packages
    /// </summary>
    [Required]
    public required bool IsAllInclusive { get; set; }
}
