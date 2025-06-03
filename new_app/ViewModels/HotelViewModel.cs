using HotelReservationSystem.Models;
using System.Collections.Generic;

namespace HotelReservationSystem.ViewModels
{
    public class HotelViewModel
    {
        public Hotel? Hotel { get; set; }
        public IEnumerable<Country>? Countries { get; set; }
    }
}