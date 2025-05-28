using HotelReservationSystem.Core.DTOs;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Core.Services;

public interface ICountryService
{
    Task<IEnumerable<CountryDto>> GetAllCountriesAsync();
    Task<CountryDto?> GetCountryByIdAsync(int id);
    Task<int> CreateCountryAsync(CountryDto countryDto);
    Task UpdateCountryAsync(int id, CountryDto countryDto);
    Task DeleteCountryAsync(int id);
}