using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Core.ViewModels
{
    public class OrderViewModel
    {
        public int Id { get; set; }
        public Customer? Customer { get; set; }
        public int CustomerId { get; set; }
        public Hotel? Hotel { get; set; }
        public int HotelId { get; set; }
        public DateTime DateOrdered { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public int NumberOfDays { get; set; }
        public double FullPrice { get; set; }
    }
}