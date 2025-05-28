using HotelReservationSystem.Core.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Core.Interfaces
{
    public interface IHotelRepository : IRepository<Hotel>
    {
        Task<IEnumerable<Hotel>> GetHotelsWithCountriesAsync();
        Task<Hotel?> GetHotelWithCountryAsync(int id);
    }
}