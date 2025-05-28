using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Core.Services;
using HotelReservationSystem.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Services.Services;

public class HotelService : IHotelService
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;

    public HotelService(ApplicationDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }

    public async Task<IEnumerable<HotelDto>> GetAllHotelsAsync()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return _mapper.Map<IEnumerable<HotelDto>>(hotels);
    }

    public async Task<HotelDto?> GetHotelByIdAsync(int id)
    {
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .FirstOrDefaultAsync(h => h.Id == id);
            
        return hotel != null ? _mapper.Map<HotelDto>(hotel) : null;
    }

    public async Task<int> CreateHotelAsync(HotelDto hotelDto)
    {
        var hotel = _mapper.Map<Hotel>(hotelDto);
        
        _context.Hotels.Add(hotel);
        await _context.SaveChangesAsync();
        
        return hotel.Id;
    }

    public async Task UpdateHotelAsync(int id, HotelDto hotelDto)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
            throw new KeyNotFoundException($"Hotel with ID {id} not found.");
        
        _mapper.Map(hotelDto, hotel);
        await _context.SaveChangesAsync();
    }

    public async Task DeleteHotelAsync(int id)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
            throw new KeyNotFoundException($"Hotel with ID {id} not found.");
        
        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();
    }
}