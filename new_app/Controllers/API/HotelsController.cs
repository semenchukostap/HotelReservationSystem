using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers.API
{
    /// <summary>
    /// API controller for managing hotel resources
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class HotelsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;
        private readonly ILogger<HotelsController> _logger;

        /// <summary>
        /// Constructor with dependency injection
        /// </summary>
        public HotelsController(ApplicationDbContext context, IMapper mapper, ILogger<HotelsController> logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Gets a list of all hotels
        /// </summary>
        /// <returns>List of hotels</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            _logger.LogInformation("Getting all hotels");
            
            var hotels = await _context.Hotels
                .Include(c => c.Country)
                .ToListAsync();
                
            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
        }

        /// <summary>
        /// Gets a specific hotel by id
        /// </summary>
        /// <param name="id">Hotel Id</param>
        /// <returns>Hotel information</returns>
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            _logger.LogInformation("Getting hotel with id: {HotelId}", id);
            
            var hotel = await _context.Hotels
                .Include(h => h.Country)
                .SingleOrDefaultAsync(c => c.Id == id);

            if (hotel == null)
            {
                _logger.LogWarning("Hotel with id: {HotelId} not found", id);
                return NotFound();
            }

            return Ok(_mapper.Map<HotelDto>(hotel));
        }

        /// <summary>
        /// Creates a new hotel
        /// </summary>
        /// <param name="hotelDto">Hotel data</param>
        /// <returns>Created hotel</returns>
        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state for creating hotel");
                return BadRequest(ModelState);
            }

            var hotel = _mapper.Map<Hotel>(hotelDto);

            _context.Hotels.Add(hotel);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created new hotel with id: {HotelId}", hotel.Id);
            
            hotelDto.Id = hotel.Id;

            return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
        }

        /// <summary>
        /// Updates an existing hotel
        /// </summary>
        /// <param name="id">Hotel Id</param>
        /// <param name="hotelDto">Updated hotel data</param>
        /// <returns>No content if successful</returns>
        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
        {
            if (id != hotelDto.Id || !ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state or id mismatch for updating hotel: {HotelId}", id);
                return BadRequest();
            }

            var hotelInDb = await _context.Hotels.FindAsync(id);

            if (hotelInDb == null)
            {
                _logger.LogWarning("Hotel with id: {HotelId} not found for update", id);
                return NotFound();
            }

            _mapper.Map(hotelDto, hotelInDb);
            
            try
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated hotel with id: {HotelId}", id);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                if (!await HotelExists(id))
                {
                    _logger.LogWarning("Hotel with id: {HotelId} no longer exists", id);
                    return NotFound();
                }
                else
                {
                    _logger.LogError(ex, "Concurrency error updating hotel: {HotelId}", id);
                    throw;
                }
            }

            return NoContent();
        }

        /// <summary>
        /// Deletes a hotel
        /// </summary>
        /// <param name="id">Hotel Id</param>
        /// <returns>No content if successful</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> DeleteHotel(int id)
        {
            var hotel = await _context.Hotels.FindAsync(id);

            if (hotel == null)
            {
                _logger.LogWarning("Hotel with id: {HotelId} not found for deletion", id);
                return NotFound();
            }

            _context.Hotels.Remove(hotel);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Deleted hotel with id: {HotelId}", id);
            
            return NoContent();
        }

        /// <summary>
        /// Checks if a hotel exists
        /// </summary>
        /// <param name="id">Hotel Id</param>
        /// <returns>True if hotel exists, false otherwise</returns>
        private async Task<bool> HotelExists(int id)
        {
            return await _context.Hotels.AnyAsync(h => h.Id == id);
        }
    }
}