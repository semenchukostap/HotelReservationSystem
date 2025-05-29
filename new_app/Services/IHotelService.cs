using HotelReservationSystem.Models;

namespace HotelReservationSystem.Services;

public interface IHotelService
{
    Task<IEnumerable<Hotel>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<Hotel?> GetByIdAsync(int id, CancellationToken cancellationToken = default);
    Task<IEnumerable<Country>> GetCountriesAsync(CancellationToken cancellationToken = default);
    Task<Hotel> CreateAsync(Hotel hotel, CancellationToken cancellationToken = default);
    Task<bool> UpdateAsync(Hotel hotel, CancellationToken cancellationToken = default);
    Task<Country> CreateCountryAsync(Country country, CancellationToken cancellationToken = default);
    Task<bool> UpdateCountryAsync(Country country, CancellationToken cancellationToken = default);
    Task<bool> HotelExistsAsync(int id, CancellationToken cancellationToken = default);
    Task<Country?> GetCountryByIdAsync(int id, CancellationToken cancellationToken = default);
    ValueTask<bool> DeleteAsync(int id, CancellationToken cancellationToken = default);
    ValueTask<bool> DeleteCountryAsync(int id, CancellationToken cancellationToken = default);
}