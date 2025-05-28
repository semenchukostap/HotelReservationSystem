using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel in the reservation system
    /// </summary>
    public class Hotel
    {
        /// <summary>
        /// Unique identifier for the hotel
        /// </summary>
        [Display(Name = "Hotel ID")]
        public int Id { get; set; }

        /// <summary>
        /// Name of the hotel
        /// </summary>
        [Required(ErrorMessage = "Hotel name is required")]
        [StringLength(255, ErrorMessage = "Hotel name cannot exceed 255 characters")]
        [Display(Name = "Hotel Name")]
        public required string Name { get; set; }

        /// <summary>
        /// Country object associated with the hotel
        /// </summary>
        [ValidateNever]
        public Country? Country { get; set; }

        /// <summary>
        /// Foreign key for the country
        /// </summary>
        [Required(ErrorMessage = "Country is required")]
        [Display(Name = "Country")]
        public int CountryId { get; set; }

        /// <summary>
        /// City where the hotel is located
        /// </summary>
        [Required(ErrorMessage = "City is required")]
        [StringLength(50, ErrorMessage = "City name cannot exceed 50 characters")]
        [Display(Name = "City")]
        public required string City { get; set; }

        /// <summary>
        /// Star rating of the hotel (1-5)
        /// </summary>
        [Required(ErrorMessage = "Star rating is required")]
        [Range(1, 5, ErrorMessage = "Star rating must be between 1 and 5")]
        [Display(Name = "Stars")]
        public int Stars { get; set; }

        /// <summary>
        /// Price per night for a standard room
        /// </summary>
        [Required(ErrorMessage = "Price is required")]
        [Range(1, 10000, ErrorMessage = "Price must be between 1 and 10,000")]
        [Display(Name = "Price Per Night")]
        [DataType(DataType.Currency)]
        public double PricePerNight { get; set; }

        /// <summary>
        /// Indicates whether the hotel offers all-inclusive packages
        /// </summary>
        [Required]
        [Display(Name = "All Inclusive")]
        public bool IsAllInclusive { get; set; }
    }
}