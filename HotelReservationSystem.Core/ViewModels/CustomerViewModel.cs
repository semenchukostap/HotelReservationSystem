using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Core.ViewModels
{
    public class CustomerViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public DateTime? Birthdate { get; set; }
    }
}