using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Controllers.Api;

[Route("api/[controller]")]
[ApiController]
public class HotelsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;
    private readonly ILogger<HotelsController> _logger;

    public HotelsController(ApplicationDbContext context, IMapper mapper, ILogger<HotelsController> logger)
    {
        _context = context;
        _mapper = mapper;
        _logger = logger;
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
    }

    [HttpGet("{id}")]
    [AllowAnonymous]
    public async Task<ActionResult<HotelDto>> GetHotel(int id)
    {
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
            return NotFound();

        return Ok(_mapper.Map<HotelDto>(hotel));
    }

    [HttpPost]
    [Authorize(Policy = "CanManageHotels")]
    public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var hotel = _mapper.Map<Hotel>(hotelDto);

        _context.Hotels.Add(hotel);
        await _context.SaveChangesAsync();

        hotelDto.Id = hotel.Id;

        return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
    }

    [HttpPut("{id}")]
    [Authorize(Policy = "CanManageHotels")]
    public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
    {
        if (id != hotelDto.Id)
            return BadRequest();

        var hotelInDb = await _context.Hotels.FindAsync(id);

        if (hotelInDb == null)
            return NotFound();

        _mapper.Map(hotelDto, hotelInDb);
        
        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException) when (!HotelExists(id))
        {
            return NotFound();
        }

        return NoContent();
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = "CanManageHotels")]
    public async Task<IActionResult> DeleteHotel(int id)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
            return NotFound();

        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    private bool HotelExists(int id)
    {
        return _context.Hotels.Any(e => e.Id == id);
    }
}