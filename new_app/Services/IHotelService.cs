using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Services
{
    public interface IHotelService
    {
        Task<IEnumerable<Hotel>> GetAllHotelsAsync();
        Task<IEnumerable<HotelDto>> GetAllHotelDtosAsync();
        Task<Hotel?> GetHotelByIdAsync(int id);
        Task<IEnumerable<Country>> GetAllCountriesAsync();
        Task<int> CreateHotelAsync(Hotel hotel);
        Task UpdateHotelAsync(Hotel hotel);
        Task DeleteHotelAsync(int id);
    }
}