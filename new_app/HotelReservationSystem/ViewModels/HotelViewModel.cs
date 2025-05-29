using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for hotel form operations - used to combine Hotel entity with related data for forms
    /// </summary>
    public class HotelViewModel
    {
        /// <summary>
        /// Hotel entity for create/edit operations
        /// </summary>
        public Hotel Hotel { get; set; }
        
        /// <summary>
        /// Collection of countries for dropdown selection
        /// </summary>
        public IEnumerable<Country> Countries { get; set; }
        
        /// <summary>
        /// List of SelectListItem elements for country dropdown with ID/Name pairs
        /// </summary>
        public IEnumerable<SelectListItem> CountriesSelectList { get; set; }
        
        /// <summary>
        /// Title for the hotel form page
        /// </summary>
        public string Title { get; set; }
    }
}