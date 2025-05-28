#nullable enable

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a country in the hotel reservation system.
    /// </summary>
    public class Country
    {
        /// <summary>
        /// Gets or sets the unique identifier for the country.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the name of the country.
        /// </summary>
        public string Name { get; set; } = string.Empty;
    }
}
