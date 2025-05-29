using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.DTOs;

namespace HotelReservationSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HotelsApiController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;
        
        public HotelsApiController(ApplicationDbContext context, IMapper mapper)
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
                
            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
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
                return NotFound();

            return _mapper.Map<HotelDto>(hotel);
        }

        // POST: api/Hotels
        [HttpPost]
        [Authorize(Roles = "CanManageHotels")]
        public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            var hotel = _mapper.Map<Hotel>(hotelDto);
            _context.Hotels.Add(hotel);
            await _context.SaveChangesAsync();
            
            hotelDto.Id = hotel.Id;
            
            return CreatedAtAction(
                nameof(GetHotel),
                new { id = hotel.Id },
                _mapper.Map<HotelDto>(hotel));
        }

        // PUT: api/Hotels/5
        [HttpPut("{id}")]
        [Authorize(Roles = "CanManageHotels")]
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

        // DELETE: api/Hotels/5
        [HttpDelete("{id}")]
        [Authorize(Roles = "CanManageHotels")]
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
            return _context.Hotels.Any(h => h.Id == id);
        }
    }
}