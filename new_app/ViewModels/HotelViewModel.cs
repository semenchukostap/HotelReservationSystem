using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels;

public class HotelViewModel
{
    public Hotel Hotel { get; set; } = null!;
    public IEnumerable<Country> Countries { get; set; } = Enumerable.Empty<Country>();
}