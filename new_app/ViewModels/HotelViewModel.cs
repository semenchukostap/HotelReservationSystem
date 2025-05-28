using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels;

/// <summary>
/// View model for hotel form operations, containing both hotel data and available countries.
/// </summary>
public class HotelViewModel
{
    /// <summary>
    /// Gets or sets the hotel entity.
    /// </summary>
    public Hotel Hotel { get; set; } = null!;

    /// <summary>
    /// Gets or sets the collection of countries available for selection.
    /// </summary>
    public IEnumerable<Country> Countries { get; set; } = Array.Empty<Country>();
}