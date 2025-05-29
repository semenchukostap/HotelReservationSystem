using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;
using new_app.Models;

namespace new_app.Controllers.API
{
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

        // GET: api/Hotels
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _context.Hotels
                .Include(c => c.Country)
                .ToListAsync();

            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
        }

        // GET: api/Hotels/5
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _context.Hotels
                .Include(c => c.Country)
                .SingleOrDefaultAsync(c => c.Id == id);

            if (hotel == null)
                return NotFound();

            return Ok(_mapper.Map<HotelDto>(hotel));
        }

        // POST: api/Hotels
        [HttpPost]
        [Authorize(Roles = RoleName.Admin)]
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

        // PUT: api/Hotels/5
        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var hotelInDb = await _context.Hotels.FindAsync(id);

            if (hotelInDb == null)
                return NotFound();

            _mapper.Map(hotelDto, hotelInDb);

            await _context.SaveChangesAsync();

            return NoContent();
        }

        // DELETE: api/Hotels/5
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
}