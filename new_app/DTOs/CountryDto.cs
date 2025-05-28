using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs;

/// <summary>
/// Data transfer object for Country entity
/// </summary>
public class CountryDto
{
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;
}