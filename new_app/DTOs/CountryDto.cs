using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs;

/// <summary>
/// Data transfer object for Country entity
/// </summary>
public class CountryDto
{
    /// <summary>
    /// Gets or sets the unique identifier for the country
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the name of the country
    /// </summary>
    [Required]
    public required string Name { get; set; } = string.Empty;
}
