using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services;

/// <summary>
/// Service class for hotel-related operations
/// </summary>
public class HotelService : IHotelService
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;

    public HotelService(ApplicationDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }

    /// <summary>
    /// Gets all hotels with their related countries
    /// </summary>
    /// <returns>A collection of hotel DTOs</returns>
    public async Task<IEnumerable<HotelDto>> GetAllAsync()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return _mapper.Map<IEnumerable<HotelDto>>(hotels);
    }

    /// <summary>
    /// Gets a specific hotel by its ID
    /// </summary>
    /// <param name="id">The ID of the hotel to retrieve</param>
    /// <returns>The hotel DTO if found, null otherwise</returns>
    public async Task<HotelDto?> GetByIdAsync(int id)
    {
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .SingleOrDefaultAsync(h => h.Id == id);
            
        if (hotel == null)
            return null;
            
        return _mapper.Map<HotelDto>(hotel);
    }

    /// <summary>
    /// Creates a new hotel
    /// </summary>
    /// <param name="hotelDto">The hotel DTO containing the data for the new hotel</param>
    /// <returns>The created hotel DTO with its assigned ID</returns>
    public async Task<HotelDto> CreateAsync(HotelDto hotelDto)
    {
        var hotel = _mapper.Map<Hotel>(hotelDto);
        
        await _context.Hotels.AddAsync(hotel);
        await _context.SaveChangesAsync();
        
        hotelDto.Id = hotel.Id;
        return hotelDto;
    }

    /// <summary>
    /// Updates an existing hotel
    /// </summary>
    /// <param name="id">The ID of the hotel to update</param>
    /// <param name="hotelDto">The hotel DTO containing the updated data</param>
    /// <returns>True if the hotel was updated, false if not found</returns>
    public async Task<bool> UpdateAsync(int id, HotelDto hotelDto)
    {
        var hotelInDb = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);
        
        if (hotelInDb == null)
            return false;
            
        _mapper.Map(hotelDto, hotelInDb);
        await _context.SaveChangesAsync();
        
        return true;
    }

    /// <summary>
    /// Deletes a hotel by its ID
    /// </summary>
    /// <param name="id">The ID of the hotel to delete</param>
    /// <returns>True if the hotel was deleted, false if not found</returns>
    public async Task<bool> DeleteAsync(int id)
    {
        var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);
        
        if (hotel == null)
            return false;
            
        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();
        
        return true;
    }

    /// <summary>
    /// Gets all countries
    /// </summary>
    /// <returns>A collection of countries</returns>
    public async Task<IEnumerable<Country>> GetCountriesAsync()
    {
        return await _context.Countries.ToListAsync();
    }

    /// <summary>
    /// Gets all countries as DTOs
    /// </summary>
    /// <returns>A collection of country DTOs</returns>
    public async Task<IEnumerable<CountryDto>> GetCountryDtosAsync()
    {
        var countries = await _context.Countries.ToListAsync();
        return _mapper.Map<IEnumerable<CountryDto>>(countries);
    }

    /// <summary>
    /// Creates a new country
    /// </summary>
    /// <param name="country">The country to create</param>
    /// <returns>The created country with its assigned ID</returns>
    public async Task<Country> CreateCountryAsync(Country country)
    {
        await _context.Countries.AddAsync(country);
        await _context.SaveChangesAsync();
        
        return country;
    }

    /// <summary>
    /// Creates a new country from DTO
    /// </summary>
    /// <param name="countryDto">The country DTO to create</param>
    /// <returns>The created country DTO with its assigned ID</returns>
    public async Task<CountryDto> CreateCountryFromDtoAsync(CountryDto countryDto)
    {
        var country = _mapper.Map<Country>(countryDto);
        
        await _context.Countries.AddAsync(country);
        await _context.SaveChangesAsync();
        
        countryDto.Id = country.Id;
        return countryDto;
    }

    /// <summary>
    /// Updates an existing country
    /// </summary>
    /// <param name="id">The ID of the country to update</param>
    /// <param name="country">The country with updated data</param>
    /// <returns>True if the country was updated, false if not found</returns>
    public async Task<bool> UpdateCountryAsync(int id, Country country)
    {
        var countryInDb = await _context.Countries.SingleOrDefaultAsync(c => c.Id == id);
        
        if (countryInDb == null)
            return false;
            
        countryInDb.Name = country.Name;
        await _context.SaveChangesAsync();
        
        return true;
    }

    /// <summary>
    /// Gets a country by its ID
    /// </summary>
    /// <param name="id">The ID of the country to retrieve</param>
    /// <returns>The country if found, null otherwise</returns>
    public async Task<Country?> GetCountryByIdAsync(int id)
    {
        return await _context.Countries.SingleOrDefaultAsync(c => c.Id == id);
    }
}