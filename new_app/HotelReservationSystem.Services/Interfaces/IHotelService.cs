using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Services
{
    public interface IHotelService
    {
        Task<IEnumerable<HotelDto>> GetAllHotelsAsync();
        Task<HotelDto?> GetHotelByIdAsync(int id);
        Task<Hotel?> GetHotelEntityByIdAsync(int id);
        Task CreateHotelAsync(HotelDto hotelDto);
        Task UpdateHotelAsync(int id, HotelDto hotelDto);
        Task DeleteHotelAsync(int id);
    }
}