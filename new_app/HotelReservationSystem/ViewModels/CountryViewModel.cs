using System;
using System.ComponentModel.DataAnnotations;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for country form operations
    /// </summary>
    public class CountryViewModel
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Country name is required")]
        [Display(Name = "Country Name")]
        [MaxLength(255, ErrorMessage = "Country name cannot exceed 255 characters")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Default constructor
        /// </summary>
        public CountryViewModel()
        {
        }

        /// <summary>
        /// Constructor to map from Country domain model
        /// </summary>
        /// <param name="country">Country model to map from</param>
        public CountryViewModel(Country country)
        {
            if (country == null)
                throw new ArgumentNullException(nameof(country));

            Id = country.Id;
            Name = country.Name ?? string.Empty;
        }

        /// <summary>
        /// Maps view model to domain model
        /// </summary>
        /// <returns>Country domain model</returns>
        public Country ToCountryModel()
        {
            return new Country
            {
                Id = Id,
                Name = Name
            };
        }
    }
}