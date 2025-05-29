using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data transfer object for hotel data used in API responses and requests
    /// </summary>
    public class HotelDto
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [Required]
        [StringLength(255)]
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [Required]
        [JsonPropertyName("countryId")]
        public int CountryId { get; set; }

        [JsonPropertyName("country")]
        public CountryDto Country { get; set; }

        [Required]
        [StringLength(50)]
        [JsonPropertyName("city")]
        public string City { get; set; }

        [Required]
        [Range(1, 5)]
        [JsonPropertyName("stars")]
        public int Stars { get; set; }

        [Required]
        [Range(1, 1000)]
        [JsonPropertyName("pricePerNight")]
        public double PricePerNight { get; set; }

        [Required]
        [JsonPropertyName("isAllInclusive")]
        public bool IsAllInclusive { get; set; }
    }
}