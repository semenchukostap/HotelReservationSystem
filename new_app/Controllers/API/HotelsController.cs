using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers.API;

[Route("api/[controller]")]
[ApiController]
public class HotelsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;

    public HotelsController(ApplicationDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }

    // GET: api/hotels
    [HttpGet]
    public async Task<IActionResult> GetHotels()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        var hotelDtos = hotels.Select(h => new HotelDto
        {
            Id = h.Id,
            Name = h.Name,
            City = h.City,
            Stars = h.Stars,
            PricePerNight = h.PricePerNight,
            IsAllInclusive = h.IsAllInclusive,
            CountryName = h.Country?.Name
        });
        
        return Ok(hotelDtos);
    }

    // GET: api/hotels/{id}
    [HttpGet("{id}")]
    public async Task<IActionResult> GetHotel(int id)
    {
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
            return NotFound();

        var hotelDto = new HotelDto
        {
            Id = hotel.Id,
            Name = hotel.Name,
            City = hotel.City,
            Stars = hotel.Stars,
            PricePerNight = hotel.PricePerNight,
            IsAllInclusive = hotel.IsAllInclusive,
            CountryName = hotel.Country?.Name
        };

        return Ok(hotelDto);
    }

    // POST: api/hotels
    [HttpPost]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> CreateHotel([FromBody] Hotel hotel)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        _context.Hotels.Add(hotel);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotel);
    }

    // PUT: api/hotels/{id}
    [HttpPut("{id}")]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> UpdateHotel(int id, [FromBody] Hotel hotel)
    {
        if (id != hotel.Id)
            return BadRequest();

        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        _context.Entry(hotel).State = EntityState.Modified;

        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            if (!await _context.Hotels.AnyAsync(h => h.Id == id))
                return NotFound();
            throw;
        }

        return NoContent();
    }

    // DELETE: api/hotels/{id}
    [HttpDelete("{id}")]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> DeleteHotel(int id)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        if (hotel == null)
            return NotFound();

        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}