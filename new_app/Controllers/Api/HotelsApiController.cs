using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Controllers.Api;

[Produces("application/json")]
[Route("api/v1/[controller]")]
[ApiController]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class HotelsController : ControllerBase
{
    private readonly ILogger<HotelsController> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;

    public HotelsController(
        ILogger<HotelsController> logger,
        ApplicationDbContext context, 
        IMapper mapper)
    {
        _logger = logger;
        _context = context;
        _mapper = mapper;
    }

    /// <summary>
    /// Retrieves all hotels.
    /// </summary>
    /// <returns>A list of all hotels.</returns>
    /// <response code="200">Returns the list of hotels</response>
    /// <response code="401">If the user is not authenticated</response>
    /// <response code="403">If the user is not authorized</response>
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [HttpGet]
    [AllowAnonymous]
    public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
    {
        try
        {
            _logger.LogInformation("Getting all hotels");
            
            var hotels = await _context.Hotels
                .Include(c => c.Country)
                .ToListAsync();
                
            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving hotels");
            return StatusCode(StatusCodes.Status500InternalServerError, 
                "An error occurred while retrieving hotels");
        }
    }

    /// <summary>
    /// Gets a specific hotel by id.
    /// </summary>
    /// <param name="id">The id of the hotel to retrieve</param>
    /// <returns>The requested hotel</returns>
    /// <response code="200">Returns the requested hotel</response>
    /// <response code="404">If the hotel is not found</response>
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [HttpGet("{id}")]
    [AllowAnonymous]
    public async Task<ActionResult<HotelDto>> GetHotel(int id)
    {
        try
        {
            _logger.LogInformation("Getting hotel with ID: {HotelId}", id);

            var hotel = await _context.Hotels
                .Include(h => h.Country)
                .SingleOrDefaultAsync(c => c.Id == id);

            if (hotel == null)
            {
                _logger.LogWarning("Hotel with ID {HotelId} not found", id);
                return NotFound($"Hotel with ID {id} not found");
            }

            return Ok(_mapper.Map<HotelDto>(hotel));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while retrieving hotel with ID {HotelId}", id);
            return StatusCode(StatusCodes.Status500InternalServerError, 
                "An error occurred while retrieving the hotel");
        }
    }

    /// <summary>
    /// Creates a new hotel.
    /// </summary>
    /// <param name="hotelDto">The hotel to create</param>
    /// <returns>The created hotel</returns>
    /// <response code="201">Returns the newly created hotel</response>
    /// <response code="400">If the hotel data is invalid</response>
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [HttpPost]
    public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state for hotel creation");
                return BadRequest(ModelState);
            }

            var hotel = _mapper.Map<Hotel>(hotelDto);

            _context.Hotels.Add(hotel);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created new hotel with ID: {HotelId}", hotel.Id);

            hotelDto.Id = hotel.Id;
            return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while creating hotel");
            return StatusCode(StatusCodes.Status500InternalServerError, 
                "An error occurred while creating the hotel");
        }
    }

    /// <summary>
    /// Updates a specific hotel.
    /// </summary>
    /// <param name="id">The id of the hotel to update</param>
    /// <param name="hotelDto">The updated hotel data</param>
    /// <returns>No content</returns>
    /// <response code="204">If the hotel was successfully updated</response>
    /// <response code="400">If the hotel data is invalid</response>
    /// <response code="404">If the hotel is not found</response>
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
    {
        try
        {
            if (id != hotelDto.Id)
            {
                _logger.LogWarning("ID mismatch in hotel update. Path ID: {PathId}, DTO ID: {DtoId}", id, hotelDto.Id);
                return BadRequest("ID mismatch");
            }

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state for hotel update");
                return BadRequest(ModelState);
            }

            var hotelInDb = await _context.Hotels.SingleOrDefaultAsync(c => c.Id == id);

            if (hotelInDb == null)
            {
                _logger.LogWarning("Hotel with ID {HotelId} not found for update", id);
                return NotFound($"Hotel with ID {id} not found");
            }

            _mapper.Map(hotelDto, hotelInDb);

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex, "Concurrency error occurred while updating hotel {HotelId}", id);
                return StatusCode(StatusCodes.Status409Conflict, 
                    "A concurrency error occurred while updating the hotel");
            }

            _logger.LogInformation("Updated hotel with ID: {HotelId}", id);
            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while updating hotel {HotelId}", id);
            return StatusCode(StatusCodes.Status500InternalServerError, 
                "An error occurred while updating the hotel");
        }
    }

    /// <summary>
    /// Deletes a specific hotel.
    /// </summary>
    /// <param name="id">The id of the hotel to delete</param>
    /// <returns>No content</returns>
    /// <response code="204">If the hotel was successfully deleted</response>
    /// <response code="404">If the hotel is not found</response>
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteHotel(int id)
    {
        try
        {
            _logger.LogInformation("Attempting to delete hotel with ID: {HotelId}", id);

            var hotel = await _context.Hotels.SingleOrDefaultAsync(c => c.Id == id);

            if (hotel == null)
            {
                _logger.LogWarning("Hotel with ID {HotelId} not found for deletion", id);
                return NotFound($"Hotel with ID {id} not found");
            }

            _context.Hotels.Remove(hotel);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Deleted hotel with ID: {HotelId}", id);
            return NoContent();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while deleting hotel {HotelId}", id);
            return StatusCode(StatusCodes.Status500InternalServerError, 
                "An error occurred while deleting the hotel");
        }
    }
}