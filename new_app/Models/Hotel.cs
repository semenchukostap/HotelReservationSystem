using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel entity in the reservation system with accommodation details
    /// </summary>
    public class Hotel
    {
        /// <summary>
        /// Unique identifier for the hotel in the database
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Official name of the hotel establishment
        /// </summary>
        [Required]
        [MaxLength(255)]
        [Display(Name = "Hotel Official Name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// The country where the hotel is located with full details
        /// </summary>
        public Country? Country { get; set; }

        /// <summary>
        /// Foreign key reference to the country where the hotel is located
        /// </summary>
        [Required]
        [Display(Name = "Hotel Country")]
        public int CountryId { get; set; }

        /// <summary>
        /// City or municipality where the hotel is situated
        /// </summary>
        [Required]
        [MaxLength(50)]
        [Display(Name = "Located City")]
        public string City { get; set; } = string.Empty;

        /// <summary>
        /// Official star rating of the hotel on a scale from 1 to 5
        /// </summary>
        [Required]
        [Range(1, 5)]
        [Display(Name = "Hotel Star Rating")]
        public int Stars { get; set; }

        /// <summary>
        /// Base price per night for a standard room in US dollars
        /// </summary>
        [Required]
        [Range(1, 1000)]
        [Display(Name = "Standard Room Price (USD)")]
        public double PricePerNight { get; set; }

        /// <summary>
        /// Indicates whether the hotel offers all-inclusive packages with meals and amenities
        /// </summary>
        [Required]
        [Display(Name = "All-Inclusive Option Available")]
        public bool IsAllInclusive { get; set; }
    }
}
