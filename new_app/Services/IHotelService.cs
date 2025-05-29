using HotelReservationSystem.Models;

namespace HotelReservationSystem.Services;

public interface IHotelService
{
    Task<IEnumerable<Hotel>> GetAllAsync();
    Task<Hotel?> GetByIdAsync(int id);
    Task<IEnumerable<Country>> GetCountriesAsync();
    Task<Hotel> CreateAsync(Hotel hotel);
    Task UpdateAsync(Hotel hotel);
    Task<Country> CreateCountryAsync(Country country);
    Task UpdateCountryAsync(Country country);
    Task<bool> HotelExistsAsync(int id);
    Task<Country?> GetCountryByIdAsync(int id);
}