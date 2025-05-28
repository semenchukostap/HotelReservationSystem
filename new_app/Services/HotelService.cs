using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services
{
    public class HotelService : IHotelService
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;

        public HotelService(ApplicationDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        public async Task<IEnumerable<Hotel>> GetAllHotelsAsync()
        {
            return await _context.Hotels
                .Include(h => h.Country)
                .ToListAsync();
        }

        public async Task<IEnumerable<HotelDto>> GetAllHotelDtosAsync()
        {
            var hotels = await _context.Hotels
                .Include(h => h.Country)
                .ToListAsync();
                
            return _mapper.Map<IEnumerable<HotelDto>>(hotels);
        }

        public async Task<Hotel?> GetHotelByIdAsync(int id)
        {
            return await _context.Hotels
                .Include(h => h.Country)
                .SingleOrDefaultAsync(h => h.Id == id);
        }

        public async Task<IEnumerable<Country>> GetAllCountriesAsync()
        {
            return await _context.Countries.ToListAsync();
        }

        public async Task<int> CreateHotelAsync(Hotel hotel)
        {
            _context.Hotels.Add(hotel);
            await _context.SaveChangesAsync();
            return hotel.Id;
        }

        public async Task UpdateHotelAsync(Hotel hotel)
        {
            _context.Update(hotel);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteHotelAsync(int id)
        {
            var hotel = await _context.Hotels.FindAsync(id);
            if (hotel != null)
            {
                _context.Hotels.Remove(hotel);
                await _context.SaveChangesAsync();
            }
        }
    }
}