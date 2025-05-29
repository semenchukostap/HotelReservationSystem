using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels
{
    public class NewOrderViewModel
    {
        public IEnumerable<Customer>? Customers { get; set; }
        public IEnumerable<Hotel>? Hotels { get; set; }
    }
}