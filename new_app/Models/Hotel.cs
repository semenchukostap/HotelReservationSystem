using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel in the system with its details and pricing information
    /// </summary>
    public class Hotel
    {
        /// <summary>
        /// The unique identifier for the hotel
        /// </summary>
        [Display(Name = "Hotel ID")]
        public int Id { get; set; }

        /// <summary>
        /// The name of the hotel
        /// </summary>
        [Required(ErrorMessage = "The hotel name is required")]
        [StringLength(255, ErrorMessage = "Name cannot exceed 255 characters")]
        [Display(Name = "Hotel Name")]
        public required string Name { get; set; }

        /// <summary>
        /// The country where the hotel is located
        /// </summary>
        [ValidateNever]
        public Country? Country { get; set; }

        /// <summary>
        /// The country ID where the hotel is located
        /// </summary>
        [Required(ErrorMessage = "Please select a country")]
        [Display(Name = "Country")]
        public int CountryId { get; set; }

        /// <summary>
        /// The city where the hotel is located
        /// </summary>
        [Required(ErrorMessage = "City is required")]
        [StringLength(50, ErrorMessage = "City name cannot exceed 50 characters")]
        [Display(Name = "City")]
        public required string City { get; set; }

        /// <summary>
        /// The quality rating of the hotel (in stars)
        /// </summary>
        [Required(ErrorMessage = "Please specify the star rating")]
        [Range(1, 5, ErrorMessage = "Stars must be between 1 and 5")]
        [Display(Name = "Star Rating")]
        public int Stars { get; set; }

        /// <summary>
        /// The price per night in USD
        /// </summary>
        [Required(ErrorMessage = "Price is required")]
        [Range(1, 1000, ErrorMessage = "Price must be between 1 and 1000")]
        [Display(Name = "Price Per Night")]
        [DataType(DataType.Currency)]
        public double PricePerNight { get; set; }

        /// <summary>
        /// Indicates if the hotel offers all-inclusive packages
        /// </summary>
        [Required]
        [Display(Name = "All Inclusive")]
        public bool IsAllInclusive { get; set; }
    }
}