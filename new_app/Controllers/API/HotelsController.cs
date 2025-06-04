using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;
using new_app.Models;
using Microsoft.AspNetCore.Authorization;

namespace new_app.Controllers.API;

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
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
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
    [Authorize(Roles = RoleName.Admin)]
    public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var hotel = _mapper.Map<Hotel>(hotelDto);

        await _context.Hotels.AddAsync(hotel);
        await _context.SaveChangesAsync();

        hotelDto.Id = hotel.Id;

        return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
    }

    // PUT: api/Hotels/5
    [HttpPut("{id}")]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
    {
        if (id != hotelDto.Id)
        {
            return BadRequest("Id mismatch");
        }

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

        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            if (!await HotelExists(id))
            {
                return NotFound();
            }
            else
            {
                throw;
            }
        }

        return NoContent();
    }

    // DELETE: api/Hotels/5
    [HttpDelete("{id}")]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> DeleteHotel(int id)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
        {
            return NotFound();
        }

        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    private async Task<bool> HotelExists(int id)
    {
        return await _context.Hotels.AnyAsync(h => h.Id == id);
    }
}