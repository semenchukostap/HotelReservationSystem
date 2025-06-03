using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;
using new_app.Models;

namespace new_app.Controllers.Api
{
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

        [HttpGet]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _context.Hotels
                .Include(h => h.Country)
                .ToListAsync();

            return _mapper.Map<List<HotelDto>>(hotels);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _context.Hotels
                .Include(h => h.Country)
                .FirstOrDefaultAsync(h => h.Id == id);

            if (hotel == null)
                return NotFound();

            return _mapper.Map<HotelDto>(hotel);
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

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var hotel = await _context.Hotels.FindAsync(id);
            if (hotel == null)
                return NotFound();

            _mapper.Map(hotelDto, hotel);

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await HotelExists(id))
                    return NotFound();
                throw;
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

        private async Task<bool> HotelExists(int id)
        {
            return await _context.Hotels.AnyAsync(h => h.Id == id);
        }
    }
}