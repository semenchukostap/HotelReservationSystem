using HotelReservationSystem.Models;
using System.Collections.Generic;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for creating new orders, containing collections of customers and hotels for dropdown/selection
    /// </summary>
    public class NewOrderViewModel
    {
        /// <summary>
        /// Collection of customers for customer selection dropdown
        /// </summary>
        public IEnumerable<Customer>? Customers { get; set; }
        
        /// <summary>
        /// Collection of hotels for hotel selection dropdown
        /// </summary>
        public IEnumerable<Hotel>? Hotels { get; set; }
    }
}
