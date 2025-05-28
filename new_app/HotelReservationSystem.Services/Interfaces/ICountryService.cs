using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Services
{
    public interface ICountryService
    {
        Task<IEnumerable<CountryDto>> GetAllCountriesAsync();
        Task<CountryDto?> GetCountryByIdAsync(int id);
        Task<IEnumerable<Country>> GetAllCountriesEntitiesAsync();
        Task CreateCountryAsync(CountryDto countryDto);
    }
}