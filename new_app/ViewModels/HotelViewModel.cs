using HotelReservationSystem.Web.Models;

namespace HotelReservationSystem.Web.ViewModels;

public class HotelViewModel
{
    public Hotel Hotel { get; set; } = null!;
    public IEnumerable<Country> Countries { get; set; } = new List<Country>();
}