using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel entity in the reservation system
    /// </summary>
    public class Hotel
    {
        /// <summary>
        /// Unique identifier for the hotel
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Name of the hotel
        /// </summary>
        [Required]
        [MaxLength(255)]
        [Display(Name = "Hotel Name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// The country where the hotel is located
        /// </summary>
        public Country? Country { get; set; }

        /// <summary>
        /// Foreign key for the country
        /// </summary>
        [Required]
        [Display(Name = "Country Location")]
        public int CountryId { get; set; }

        /// <summary>
        /// City where the hotel is located
        /// </summary>
        [Required]
        [MaxLength(50)]
        [Display(Name = "City")]
        public string City { get; set; } = string.Empty;

        /// <summary>
        /// Star rating of the hotel (1-5)
        /// </summary>
        [Required]
        [Range(1, 5)]
        [Display(Name = "Star Rating")]
        public int Stars { get; set; }

        /// <summary>
        /// Price per night for a standard room
        /// </summary>
        [Required]
        [Range(1, 1000)]
        [Display(Name = "Price Per Night ($)")]
        public double PricePerNight { get; set; }

        /// <summary>
        /// Indicates whether the hotel offers all-inclusive packages
        /// </summary>
        [Required]
        [Display(Name = "All Inclusive")]
        public bool IsAllInclusive { get; set; }
    }
}