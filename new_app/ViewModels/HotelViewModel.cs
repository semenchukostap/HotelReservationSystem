using HotelReservationSystem.Models;
using System.Collections.Generic;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for hotel-related operations
    /// </summary>
    public class HotelViewModel
    {
        /// <summary>
        /// The hotel entity
        /// </summary>
        public Hotel? Hotel { get; set; }

        /// <summary>
        /// Collection of available countries for hotel location
        /// </summary>
        public IEnumerable<Country>? Countries { get; set; }
        
        /// <summary>
        /// Gets the appropriate title based on whether this is an edit or create operation
        /// </summary>
        public string Title => Hotel?.Id != 0 ? "Edit Hotel" : "New Hotel";
    }
}