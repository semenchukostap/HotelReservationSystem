using HotelReservationSystem.Core.DTOs;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Core.Services;

public interface IHotelService
{
    Task<IEnumerable<HotelDto>> GetAllHotelsAsync();
    Task<HotelDto?> GetHotelByIdAsync(int id);
    Task<int> CreateHotelAsync(HotelDto hotelDto);
    Task UpdateHotelAsync(int id, HotelDto hotelDto);
    Task DeleteHotelAsync(int id);
}