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
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
    {
        _logger.LogInformation("Getting all hotels");
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
    }

    [HttpGet("{id:int}")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<HotelDto>> GetHotel(int id)
    {
        _logger.LogInformation("Getting hotel with ID {HotelId}", id);
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
        {
            _logger.LogWarning("Hotel with ID {HotelId} not found", id);
            return NotFound();
        }

        return Ok(_mapper.Map<HotelDto>(hotel));
    }

    [HttpPost]
    [Authorize(Policy = "CanManageHotels")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<HotelDto>> CreateHotel([FromBody] HotelDto hotelDto)
    {
        _logger.LogInformation("Creating a new hotel");
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Invalid model state for hotel creation");
            return BadRequest(ModelState);
        }

        var hotel = _mapper.Map<Hotel>(hotelDto);

        _context.Hotels.Add(hotel);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Hotel created with ID {HotelId}", hotel.Id);
        hotelDto.Id = hotel.Id;

        return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
    }

    [HttpPut("{id:int}")]
    [Authorize(Policy = "CanManageHotels")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateHotel(int id, [FromBody] HotelDto hotelDto)
    {
        _logger.LogInformation("Updating hotel with ID {HotelId}", id);
        if (id != hotelDto.Id)
        {
            _logger.LogWarning("Hotel ID mismatch: {PathId} vs {DtoId}", id, hotelDto.Id);
            return BadRequest();
        }

        var hotelInDb = await _context.Hotels.FindAsync(id);

        if (hotelInDb == null)
        {
            _logger.LogWarning("Hotel with ID {HotelId} not found for update", id);
            return NotFound();
        }

        _mapper.Map(hotelDto, hotelInDb);
        
        try
        {
            await _context.SaveChangesAsync();
            _logger.LogInformation("Hotel with ID {HotelId} updated successfully", id);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            if (!HotelExists(id))
            {
                _logger.LogWarning("Hotel with ID {HotelId} no longer exists", id);
                return NotFound();
            }
            _logger.LogError(ex, "Concurrency error when updating hotel {HotelId}", id);
            throw;
        }

        return NoContent();
    }

    [HttpDelete("{id:int}")]
    [Authorize(Policy = "CanManageHotels")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteHotel(int id)
    {
        _logger.LogInformation("Deleting hotel with ID {HotelId}", id);
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
        {
            _logger.LogWarning("Hotel with ID {HotelId} not found for deletion", id);
            return NotFound();
        }

        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Hotel with ID {HotelId} deleted successfully", id);
        return NoContent();
    }

    private bool HotelExists(int id)
    {
        return _context.Hotels.Any(e => e.Id == id);
    }
}