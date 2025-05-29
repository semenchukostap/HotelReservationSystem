using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;
using HotelReservationSystem.Data;

namespace HotelReservationSystem.Services;

public class HotelService : IHotelService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<HotelService> _logger;

    public HotelService(ApplicationDbContext context, ILogger<HotelService> logger)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IEnumerable<Hotel>> GetAllAsync()
    {
        return await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
    }

    public async Task<Hotel?> GetByIdAsync(int id)
    {
        return await _context.Hotels
            .Include(h => h.Country)
            .FirstOrDefaultAsync(h => h.Id == id);
    }

    public async Task<IEnumerable<Country>> GetCountriesAsync()
    {
        return await _context.Countries.ToListAsync();
    }

    public async Task<Hotel> CreateAsync(Hotel hotel)
    {
        if (hotel == null)
            throw new ArgumentNullException(nameof(hotel));

        await _context.Hotels.AddAsync(hotel);
        await _context.SaveChangesAsync();
        return hotel;
    }

    public async Task UpdateAsync(Hotel hotel)
    {
        if (hotel == null)
            throw new ArgumentNullException(nameof(hotel));

        var hotelInDb = await _context.Hotels.FindAsync(hotel.Id);
        if (hotelInDb == null)
            throw new KeyNotFoundException($"Hotel with ID {hotel.Id} not found.");

        hotelInDb.Name = hotel.Name;
        hotelInDb.City = hotel.City;
        hotelInDb.CountryId = hotel.CountryId;
        hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
        hotelInDb.PricePerNight = hotel.PricePerNight;
        hotelInDb.Stars = hotel.Stars;

        await _context.SaveChangesAsync();
    }

    public async Task<Country> CreateCountryAsync(Country country)
    {
        if (country == null)
            throw new ArgumentNullException(nameof(country));

        await _context.Countries.AddAsync(country);
        await _context.SaveChangesAsync();
        return country;
    }

    public async Task UpdateCountryAsync(Country country)
    {
        if (country == null)
            throw new ArgumentNullException(nameof(country));

        var countryInDb = await _context.Countries.FindAsync(country.Id);
        if (countryInDb == null)
            throw new KeyNotFoundException($"Country with ID {country.Id} not found.");

        countryInDb.Name = country.Name;
        await _context.SaveChangesAsync();
    }

    public async Task<bool> HotelExistsAsync(int id)
    {
        return await _context.Hotels.AnyAsync(h => h.Id == id);
    }

    public async Task<Country?> GetCountryByIdAsync(int id)
    {
        return await _context.Countries.FindAsync(id);
    }
}