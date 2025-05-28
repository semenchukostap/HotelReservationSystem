using HotelReservationSystem.Core.Models;
using System.Collections.Generic;

namespace HotelReservationSystem.Web.ViewModels
{
    public class HotelViewModel
    {
        public Hotel Hotel { get; set; } = new Hotel();
        public IEnumerable<Country> Countries { get; set; } = new List<Country>();
    }
}