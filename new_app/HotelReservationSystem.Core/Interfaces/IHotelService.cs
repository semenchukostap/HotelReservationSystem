using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Core.Interfaces
{
    public interface IHotelService
    {
        Task<IEnumerable<HotelDto>> GetAllHotelsAsync();
        Task<HotelDto?> GetHotelByIdAsync(int id);
        Task<HotelDto> CreateHotelAsync(HotelDto hotelDto);
        Task UpdateHotelAsync(int id, HotelDto hotelDto);
        Task DeleteHotelAsync(int id);
    }
}