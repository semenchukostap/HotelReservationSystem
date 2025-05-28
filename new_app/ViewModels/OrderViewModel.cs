using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.ViewModels
{
    public class OrderViewModel
    {
        public Customer? Customer { get; set; }
        public IEnumerable<Customer>? Customers { get; set; }
        public IEnumerable<SelectListItem>? CustomersList { get; set; }
        
        public Hotel? Hotel { get; set; }
        public IEnumerable<Hotel>? Hotels { get; set; }
        public IEnumerable<SelectListItem>? HotelsList { get; set; }

        public DateTime StartDate { get; set; } = DateTime.Today;
        public DateTime EndDate { get; set; } = DateTime.Today.AddDays(1);
    }
}