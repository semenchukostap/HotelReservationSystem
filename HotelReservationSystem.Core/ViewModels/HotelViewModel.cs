using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Core.ViewModels;

public class HotelViewModel
{
    public Hotel? Hotel { get; set; }
    public IEnumerable<Country>? Countries { get; set; }
}