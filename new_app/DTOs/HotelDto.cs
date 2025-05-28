using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs;

/// <summary>
/// Data transfer object for hotel information
/// </summary>
public class HotelDto
{
    /// <summary>
    /// The unique identifier of the hotel
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// The name of the hotel
    /// </summary>
    [Required]
    [MaxLength(255)]
    public required string Name { get; set; } = string.Empty;

    /// <summary>
    /// The country identifier where the hotel is located
    /// </summary>
    [Required]
    public int CountryId { get; set; }
    
    /// <summary>
    /// The name of the country where the hotel is located
    /// </summary>
    public string? CountryName { get; set; }

    /// <summary>
    /// The city where the hotel is located
    /// </summary>
    [Required]
    [MaxLength(50)]
    public required string City { get; set; } = string.Empty;

    /// <summary>
    /// The star rating of the hotel (1-5)
    /// </summary>
    [Required]
    [Range(1, 5)]
    public int Stars { get; set; }

    /// <summary>
    /// The price per night for a standard room
    /// </summary>
    [Required]
    [Range(1, 1000)]
    public decimal PricePerNight { get; set; }

    /// <summary>
    /// Indicates whether the hotel offers all-inclusive packages
    /// </summary>
    [Required]
    public bool IsAllInclusive { get; set; }
}
