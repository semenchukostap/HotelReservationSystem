using HotelReservationSystem.Web.Models;

namespace HotelReservationSystem.Web.Services;

public interface IHotelService
{
    Task<IEnumerable<Hotel>> GetAllAsync();
    Task<Hotel?> GetByIdAsync(int id);
    Task<Hotel> CreateAsync(Hotel hotel);
    Task UpdateAsync(Hotel hotel);
    Task<IEnumerable<Country>> GetCountriesAsync();
    Task<Country> CreateCountryAsync(Country country);
    Task UpdateCountryAsync(Country country);
}