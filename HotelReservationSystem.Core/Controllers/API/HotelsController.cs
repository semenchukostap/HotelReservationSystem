using AutoMapper;
using HotelReservationSystem.Core.Data;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Core.Controllers.API;

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

    // GET: api/Hotels
    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
    {
        var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
        return _mapper.Map<List<HotelDto>>(hotels);
    }

    // GET: api/Hotels/5
    [HttpGet("{id}")]
    [AllowAnonymous]
    public async Task<ActionResult<HotelDto>> GetHotel(int id)
    {
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
        {
            return NotFound();
        }

        return _mapper.Map<HotelDto>(hotel);
    }

    // POST: api/Hotels
    [HttpPost]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var hotel = _mapper.Map<Hotel>(hotelDto);

        _context.Hotels.Add(hotel);
        await _context.SaveChangesAsync();

        hotelDto.Id = hotel.Id;

        return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
    }

    // PUT: api/Hotels/5
    [HttpPut("{id}")]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var hotelInDb = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

        if (hotelInDb == null)
        {
            return NotFound();
        }

        _mapper.Map(hotelDto, hotelInDb);

        await _context.SaveChangesAsync();

        return NoContent();
    }

    // DELETE: api/Hotels/5
    [HttpDelete("{id}")]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> DeleteHotel(int id)
    {
        var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
        {
            return NotFound();
        }

        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}