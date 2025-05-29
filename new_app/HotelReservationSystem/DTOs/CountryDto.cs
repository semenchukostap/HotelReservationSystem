using System;
using System.Text.Json.Serialization;

namespace HotelReservationSystem.DTOs
{
    public class CountryDto
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }
    }
}