using AutoMapper;
using HotelReservationSystem.Core.Data;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Core.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class HotelsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;
        private readonly ILogger<HotelsController> _logger;

        public HotelsController(
            ApplicationDbContext context, 
            IMapper mapper, 
            ILogger<HotelsController> logger)
        {
            _context = context;
            _mapper = mapper;
            _logger = logger;
        }

        // GET: api/Hotels
        [HttpGet]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _context.Hotels
                .Include(h => h.Country)
                .ToListAsync();
                
            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
        }

        // GET: api/Hotels/5
        [HttpGet("{id}")]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _context.Hotels
                .Include(h => h.Country)
                .SingleOrDefaultAsync(h => h.Id == id);

            if (hotel == null)
            {
                return NotFound();
            }

            return Ok(_mapper.Map<HotelDto>(hotel));
        }

        // PUT: api/Hotels/5
        [HttpPut("{id}")]
        public async Task<IActionResult> PutHotel(int id, HotelDto hotelDto)
        {
            if (id != hotelDto.Id)
            {
                return BadRequest();
            }

            var hotelInDb = await _context.Hotels.FindAsync(id);
            if (hotelInDb == null)
            {
                return NotFound();
            }

            // Update properties
            hotelInDb.Name = hotelDto.Name;
            hotelInDb.City = hotelDto.City;
            hotelInDb.CountryId = hotelDto.CountryId;
            hotelInDb.Stars = hotelDto.Stars;
            hotelInDb.PricePerNight = hotelDto.PricePerNight;
            hotelInDb.IsAllInclusive = hotelDto.IsAllInclusive;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!HotelExists(id))
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

        // POST: api/Hotels
        [HttpPost]
        public async Task<ActionResult<HotelDto>> PostHotel(HotelDto hotelDto)
        {
            var hotel = _mapper.Map<Hotel>(hotelDto);
            
            _context.Hotels.Add(hotel);
            await _context.SaveChangesAsync();

            hotelDto.Id = hotel.Id;

            return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
        }

        // DELETE: api/Hotels/5
        [HttpDelete("{id}")]
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

        private bool HotelExists(int id)
        {
            return _context.Hotels.Any(e => e.Id == id);
        }
    }
}