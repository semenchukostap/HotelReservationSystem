using System.Collections.Generic;
using System.Threading.Tasks;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Services
{
    /// <summary>
    /// Interface for hotel service operations in the HotelReservationSystem
    /// </summary>
    public interface IHotelService
    {
        /// <summary>
        /// Gets all hotels with country information
        /// </summary>
        /// <returns>Collection of hotel DTOs with country information</returns>
        Task<IEnumerable<HotelDto>> GetAllHotelsAsync();

        /// <summary>
        /// Gets a hotel by ID
        /// </summary>
        /// <param name="id">Hotel ID</param>
        /// <returns>Hotel DTO if found, null otherwise</returns>
        Task<HotelDto?> GetHotelByIdAsync(int id);

        /// <summary>
        /// Creates a new hotel
        /// </summary>
        /// <param name="hotelDto">Hotel data transfer object</param>
        /// <returns>Created hotel with generated ID</returns>
        Task<HotelDto> CreateHotelAsync(HotelDto hotelDto);

        /// <summary>
        /// Updates an existing hotel
        /// </summary>
        /// <param name="id">Hotel ID</param>
        /// <param name="hotelDto">Updated hotel data</param>
        /// <returns>True if update was successful, false otherwise</returns>
        Task<bool> UpdateHotelAsync(int id, HotelDto hotelDto);

        /// <summary>
        /// Deletes a hotel by ID
        /// </summary>
        /// <param name="id">Hotel ID</param>
        /// <returns>True if deletion was successful, false otherwise</returns>
        Task<bool> DeleteHotelAsync(int id);

        /// <summary>
        /// Gets all countries for hotel selection
        /// </summary>
        /// <returns>Collection of all countries</returns>
        Task<IEnumerable<CountryDto>> GetAllCountriesAsync();

        /// <summary>
        /// Creates a new country
        /// </summary>
        /// <param name="countryDto">Country data</param>
        /// <returns>Created country with generated ID</returns>
        Task<CountryDto> CreateCountryAsync(CountryDto countryDto);

        /// <summary>
        /// Gets a country by ID
        /// </summary>
        /// <param name="id">Country ID</param>
        /// <returns>Country DTO if found, null otherwise</returns>
        Task<CountryDto?> GetCountryByIdAsync(int id);

        /// <summary>
        /// Updates an existing country
        /// </summary>
        /// <param name="id">Country ID</param>
        /// <param name="countryDto">Updated country data</param>
        /// <returns>True if update was successful, false otherwise</returns>
        Task<bool> UpdateCountryAsync(int id, CountryDto countryDto);
    }
}