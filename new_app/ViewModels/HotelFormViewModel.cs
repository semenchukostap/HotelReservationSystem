using System.ComponentModel.DataAnnotations;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels
{
    public class HotelFormViewModel
    {
        public Hotel Hotel { get; set; } = new();
        public IEnumerable<Country> Countries { get; set; } = new List<Country>();
    }
}