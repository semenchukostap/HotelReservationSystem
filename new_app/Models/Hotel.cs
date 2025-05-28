using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

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
        [JsonPropertyName("id")]
        public int Id { get; set; }

        /// <summary>
        /// Official name of the hotel establishment
        /// </summary>
        [Required(ErrorMessage = "Hotel name is required")]
        [MaxLength(255, ErrorMessage = "Hotel name cannot exceed 255 characters")]
        [Display(Name = "Hotel Official Name")]
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// The country where the hotel is located with full details
        /// </summary>
        [JsonPropertyName("country")]
        public Country? Country { get; set; }

        /// <summary>
        /// Foreign key reference to the country where the hotel is located
        /// </summary>
        [Required(ErrorMessage = "Country must be selected")]
        [Display(Name = "Hotel Country")]
        [ForeignKey("Country")]
        [JsonPropertyName("countryId")]
        public int CountryId { get; set; }

        /// <summary>
        /// City or municipality where the hotel is situated
        /// </summary>
        [Required(ErrorMessage = "City is required")]
        [MaxLength(50, ErrorMessage = "City name cannot exceed 50 characters")]
        [Display(Name = "Located City")]
        [JsonPropertyName("city")]
        public string City { get; set; } = string.Empty;

        /// <summary>
        /// Official star rating of the hotel on a scale from 1 to 5
        /// </summary>
        [Required(ErrorMessage = "Star rating is required")]
        [Range(1, 5, ErrorMessage = "Star rating must be between 1 and 5")]
        [Display(Name = "Hotel Star Rating")]
        [JsonPropertyName("stars")]
        public int Stars { get; set; }

        /// <summary>
        /// Base price per night for a standard room in US dollars
        /// </summary>
        [Required(ErrorMessage = "Price per night is required")]
        [Range(1, 1000, ErrorMessage = "Price must be between $1 and $1000")]
        [Display(Name = "Standard Room Price (USD)")]
        [DataType(DataType.Currency)]
        [JsonPropertyName("pricePerNight")]
        public double PricePerNight { get; set; }

        /// <summary>
        /// Indicates whether the hotel offers all-inclusive packages with meals and amenities
        /// </summary>
        [Required(ErrorMessage = "All-inclusive status must be specified")]
        [Display(Name = "All-Inclusive Option Available")]
        [JsonPropertyName("isAllInclusive")]
        public bool IsAllInclusive { get; set; }
    }
}