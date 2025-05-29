using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;
using HotelReservationSystem.Data;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using FluentValidation;

namespace HotelReservationSystem.Services;

public sealed class HotelService(
    ApplicationDbContext context,
    ILogger<HotelService> logger,
    IValidator<Hotel> hotelValidator,
    IValidator<Country> countryValidator) : IHotelService
{
    private readonly ApplicationDbContext _context = context ?? throw new ArgumentNullException(nameof(context));
    private readonly ILogger<HotelService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly IValidator<Hotel> _hotelValidator = hotelValidator ?? throw new ArgumentNullException(nameof(hotelValidator));
    private readonly IValidator<Country> _countryValidator = countryValidator ?? throw new ArgumentNullException(nameof(countryValidator));

    public async Task<IEnumerable<Hotel>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var scope = _logger.BeginScope(new Dictionary<string, object> { ["Operation"] = "GetAllHotels" });
            _logger.LogInformation("Retrieving all hotels");

            var hotels = await _context.Hotels
                .Include(h => h.Country)
                .AsNoTracking()
                .TagWith("Get all hotels query")
                .AsSplitQuery()
                .ToListAsync(cancellationToken);

            _logger.LogInformation("Retrieved {Count} hotels in {ElapsedMilliseconds}ms", 
                hotels.Count, stopwatch.ElapsedMilliseconds);
            
            return hotels;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving all hotels. Elapsed time: {ElapsedMilliseconds}ms",
                stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    public async Task<Hotel?> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(id);

        try
        {
            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "GetHotelById",
                ["HotelId"] = id
            });

            _logger.LogInformation("Retrieving hotel with ID: {HotelId}", id);

            return await _context.Hotels
                .Include(h => h.Country)
                .AsNoTracking()
                .TagWith($"Get hotel by id: {id}")
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
            using var scope = _logger.BeginScope(new Dictionary<string, object> { ["Operation"] = "GetAllCountries" });
            _logger.LogInformation("Retrieving all countries");

            return await _context.Countries
                .AsNoTracking()
                .TagWith("Get all countries query")
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
            var validationResult = await _hotelValidator.ValidateAsync(hotel, cancellationToken);
            if (!validationResult.IsValid)
            {
                throw new ValidationException(validationResult.Errors);
            }

            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "CreateHotel",
                ["HotelName"] = hotel.Name
            });

            _logger.LogInformation("Creating new hotel: {HotelName}", hotel.Name);

            await _context.Hotels.AddAsync(hotel, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Successfully created hotel: {HotelName} with ID: {HotelId}", 
                hotel.Name, hotel.Id);

            return hotel;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to create hotel: {HotelName}. Database error occurred", hotel.Name);
            throw;
        }
    }

    public async Task UpdateAsync(Hotel hotel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hotel);

        try
        {
            var validationResult = await _hotelValidator.ValidateAsync(hotel, cancellationToken);
            if (!validationResult.IsValid)
            {
                throw new ValidationException(validationResult.Errors);
            }

            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "UpdateHotel",
                ["HotelId"] = hotel.Id
            });

            _logger.LogInformation("Updating hotel with ID: {HotelId}", hotel.Id);
            
            var hotelInDb = await _context.Hotels
                .FindAsync(new object[] { hotel.Id }, cancellationToken)
                ?? throw new KeyNotFoundException($"Hotel with ID {hotel.Id} not found.");

            _context.Entry(hotelInDb).CurrentValues.SetValues(hotel);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Successfully updated hotel with ID: {HotelId}", hotel.Id);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogError(ex, "Concurrency conflict while updating hotel with ID: {HotelId}", hotel.Id);
            throw;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to update hotel with ID: {HotelId}. Database error occurred", hotel.Id);
            throw;
        }
    }

    public async Task<Country> CreateCountryAsync(Country country, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(country);

        try
        {
            var validationResult = await _countryValidator.ValidateAsync(country, cancellationToken);
            if (!validationResult.IsValid)
            {
                throw new ValidationException(validationResult.Errors);
            }

            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "CreateCountry",
                ["CountryName"] = country.Name
            });

            _logger.LogInformation("Creating new country: {CountryName}", country.Name);

            await _context.Countries.AddAsync(country, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Successfully created country: {CountryName} with ID: {CountryId}", 
                country.Name, country.Id);

            return country;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to create country: {CountryName}. Database error occurred", country.Name);
            throw;
        }
    }

    public async Task UpdateCountryAsync(Country country, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(country);

        try
        {
            var validationResult = await _countryValidator.ValidateAsync(country, cancellationToken);
            if (!validationResult.IsValid)
            {
                throw new ValidationException(validationResult.Errors);
            }

            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "UpdateCountry",
                ["CountryId"] = country.Id
            });

            _logger.LogInformation("Updating country with ID: {CountryId}", country.Id);
            
            var countryInDb = await _context.Countries
                .FindAsync(new object[] { country.Id }, cancellationToken)
                ?? throw new KeyNotFoundException($"Country with ID {country.Id} not found.");

            _context.Entry(countryInDb).CurrentValues.SetValues(country);
            await _context.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Successfully updated country with ID: {CountryId}", country.Id);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogError(ex, "Concurrency conflict while updating country with ID: {CountryId}", country.Id);
            throw;
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Failed to update country with ID: {CountryId}. Database error occurred", country.Id);
            throw;
        }
    }

    public async Task<bool> HotelExistsAsync(int id, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(id);

        try
        {
            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "CheckHotelExists",
                ["HotelId"] = id
            });

            return await _context.Hotels
                .TagWith($"Check hotel exists: {id}")
                .AnyAsync(h => h.Id == id, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while checking hotel existence with ID: {HotelId}", id);
            throw;
        }
    }

    public async Task<Country?> GetCountryByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(id);

        try
        {
            using var scope = _logger.BeginScope(new Dictionary<string, object> 
            { 
                ["Operation"] = "GetCountryById",
                ["CountryId"] = id
            });

            _logger.LogInformation("Retrieving country with ID: {CountryId}", id);

            return await _context.Countries
                .AsNoTracking()
                .TagWith($"Get country by id: {id}")
                .FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving country with ID: {CountryId}", id);
            throw;
        }
    }
}