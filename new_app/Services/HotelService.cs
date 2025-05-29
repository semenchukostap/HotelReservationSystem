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

    public async Task<IEnumerable<Hotel>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Retrieving all hotels");
            return await _context.Hotels
                .Include(h => h.Country)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving all hotels");
            throw;
        }
    }

    public async Task<Hotel?> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Retrieving hotel with ID: {HotelId}", id);
            return await _context.Hotels
                .Include(h => h.Country)
                .AsNoTracking()
                .FirstOrDefaultAsync(h => h.Id == id, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving hotel with ID: {HotelId}", id);
            throw;
        }
    }

    public async Task<IEnumerable<Country>> GetCountriesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Retrieving all countries");
            return await _context.Countries
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving countries");
            throw;
        }
    }

    public async Task<Hotel> CreateAsync(Hotel hotel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hotel);

        try
        {
            _logger.LogInformation("Creating new hotel: {HotelName}", hotel.Name);
            await _context.Hotels.AddAsync(hotel, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            return hotel;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to create hotel: {HotelName}", hotel.Name);
            throw;
        }
    }

    public async Task UpdateAsync(Hotel hotel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hotel);

        try
        {
            _logger.LogInformation("Updating hotel with ID: {HotelId}", hotel.Id);
            
            var hotelInDb = await _context.Hotels.FindAsync(new object[] { hotel.Id }, cancellationToken)
                ?? throw new KeyNotFoundException($"Hotel with ID {hotel.Id} not found.");

            _context.Entry(hotelInDb).CurrentValues.SetValues(hotel);
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to update hotel with ID: {HotelId}", hotel.Id);
            throw;
        }
    }

    public async Task<Country> CreateCountryAsync(Country country, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(country);

        try
        {
            _logger.LogInformation("Creating new country: {CountryName}", country.Name);
            await _context.Countries.AddAsync(country, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            return country;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to create country: {CountryName}", country.Name);
            throw;
        }
    }

    public async Task UpdateCountryAsync(Country country, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(country);

        try
        {
            _logger.LogInformation("Updating country with ID: {CountryId}", country.Id);
            
            var countryInDb = await _context.Countries.FindAsync(new object[] { country.Id }, cancellationToken)
                ?? throw new KeyNotFoundException($"Country with ID {country.Id} not found.");

            _context.Entry(countryInDb).CurrentValues.SetValues(country);
            await _context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to update country with ID: {CountryId}", country.Id);
            throw;
        }
    }

    public async Task<bool> HotelExistsAsync(int id, CancellationToken cancellationToken = default)
    {
        try
        {
            return await _context.Hotels.AnyAsync(h => h.Id == id, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while checking hotel existence with ID: {HotelId}", id);
            throw;
        }
    }

    public async Task<Country?> GetCountryByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Retrieving country with ID: {CountryId}", id);
            return await _context.Countries
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving country with ID: {CountryId}", id);
            throw;
        }
    }
}