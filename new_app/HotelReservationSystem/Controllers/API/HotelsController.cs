using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
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

        /// <summary>
        /// Gets all hotels
        /// </summary>
        /// <returns>A list of hotel DTOs</returns>
        [HttpGet]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _context.Hotels
                .Include(c => c.Country)
                .ToListAsync();
                
            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
        }

        /// <summary>
        /// Gets a specific hotel by ID
        /// </summary>
        /// <param name="id">The hotel ID</param>
        /// <returns>The hotel DTO if found</returns>
        [HttpGet("{id}")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _context.Hotels
                .Include(c => c.Country)
                .SingleOrDefaultAsync(c => c.Id == id);

            if (hotel == null)
                return NotFound();

            return Ok(_mapper.Map<HotelDto>(hotel));
        }

        /// <summary>
        /// Creates a new hotel
        /// </summary>
        /// <param name="hotelDto">The hotel data</param>
        /// <returns>The created hotel</returns>
        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
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

        /// <summary>
        /// Updates an existing hotel
        /// </summary>
        /// <param name="id">The hotel ID</param>
        /// <param name="hotelDto">The updated hotel data</param>
        /// <returns>No content if successful</returns>
        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
        {
            if (id != hotelDto.Id)
                return BadRequest();
                
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

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

        /// <summary>
        /// Deletes a hotel
        /// </summary>
        /// <param name="id">The hotel ID</param>
        /// <returns>No content if successful</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
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
            return _context.Hotels.Any(e => e.Id == id);
        }
    }
}