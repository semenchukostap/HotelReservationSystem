using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Core.Services;
using HotelReservationSystem.Data;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Services.Services;

public class CountryService : ICountryService
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;

    public CountryService(ApplicationDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }

    public async Task<IEnumerable<CountryDto>> GetAllCountriesAsync()
    {
        var countries = await _context.Countries.ToListAsync();
        return _mapper.Map<IEnumerable<CountryDto>>(countries);
    }

    public async Task<CountryDto?> GetCountryByIdAsync(int id)
    {
        var country = await _context.Countries.FindAsync(id);
        return country != null ? _mapper.Map<CountryDto>(country) : null;
    }

    public async Task<int> CreateCountryAsync(CountryDto countryDto)
    {
        var country = _mapper.Map<Country>(countryDto);
        
        _context.Countries.Add(country);
        await _context.SaveChangesAsync();
        
        return country.Id;
    }

    public async Task UpdateCountryAsync(int id, CountryDto countryDto)
    {
        var country = await _context.Countries.FindAsync(id);
        
        if (country == null)
            throw new KeyNotFoundException($"Country with ID {id} not found.");
        
        _mapper.Map(countryDto, country);
        await _context.SaveChangesAsync();
    }

    public async Task DeleteCountryAsync(int id)
    {
        var country = await _context.Countries.FindAsync(id);
        
        if (country == null)
            throw new KeyNotFoundException($"Country with ID {id} not found.");
        
        _context.Countries.Remove(country);
        await _context.SaveChangesAsync();
    }
}