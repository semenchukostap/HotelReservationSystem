using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Data;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services
{
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

        public async Task<IEnumerable<Country>> GetAllCountriesEntitiesAsync()
        {
            return await _context.Countries.ToListAsync();
        }

        public async Task CreateCountryAsync(CountryDto countryDto)
        {
            var country = _mapper.Map<Country>(countryDto);
            _context.Countries.Add(country);
            await _context.SaveChangesAsync();
            countryDto.Id = country.Id;
        }
    }
}