using HotelReservationSystem.Core.Interfaces;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Infrastructure.Repositories
{
    public class HotelRepository : Repository<Hotel>, IHotelRepository
    {
        public HotelRepository(ApplicationDbContext context) : base(context)
        {
        }
        
        public async Task<IEnumerable<Hotel>> GetHotelsWithCountriesAsync()
        {
            return await _context.Hotels
                .Include(h => h.Country)
                .ToListAsync();
        }
        
        public async Task<Hotel?> GetHotelWithCountryAsync(int id)
        {
            return await _context.Hotels
                .Include(h => h.Country)
                .FirstOrDefaultAsync(h => h.Id == id);
        }
    }
}