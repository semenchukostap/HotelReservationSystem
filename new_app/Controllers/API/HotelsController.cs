using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers.API
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
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _context.Hotels
                .Include(c => c.Country)
                .ToListAsync();
                
            return _mapper.Map<List<HotelDto>>(hotels);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _context.Hotels
                .Include(h => h.Country)
                .SingleOrDefaultAsync(c => c.Id == id);

            if (hotel == null)
                return NotFound();

            return _mapper.Map<HotelDto>(hotel);
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
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
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
        {
            if (id != hotelDto.Id)
                return BadRequest();
                
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var hotelInDb = await _context.Hotels.SingleOrDefaultAsync(c => c.Id == id);

            if (hotelInDb == null)
                return NotFound();

            _mapper.Map(hotelDto, hotelInDb);

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await HotelExists(id))
                    return NotFound();
                else
                    throw;
            }

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
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
            return await _context.Hotels.AnyAsync(e => e.Id == id);
        }
    }
}