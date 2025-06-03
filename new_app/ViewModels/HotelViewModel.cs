using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels
{
    public class HotelViewModel
    {
        public Hotel? Hotel { get; set; }
        public IEnumerable<Country>? Countries { get; set; }
    }
}