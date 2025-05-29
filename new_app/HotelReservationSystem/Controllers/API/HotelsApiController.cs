using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers.API
{
    /// <summary>
    /// API controller for managing hotel-related operations
    /// </summary>
    [ApiVersion("1.0")]
    public class HotelsApiController : BaseApiController
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;

        /// <summary>
        /// Initializes a new instance of the HotelsApiController
        /// </summary>
        /// <param name="context">The database context</param>
        /// <param name="mapper">The AutoMapper instance</param>
        /// <param name="logger">The logger instance</param>
        public HotelsApiController(
            ApplicationDbContext context,
            IMapper mapper,
            ILogger<HotelsApiController> logger) : base(logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        }

        /// <summary>
        /// Retrieves all hotels
        /// </summary>
        /// <returns>A collection of hotels</returns>
        /// <response code="200">Returns the list of hotels</response>
        [HttpGet]
        [AllowAnonymous]
        [ProducesResponseType(typeof(IEnumerable<HotelDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            try
            {
                var hotels = await _context.Hotels
                    .Include(c => c.Country)
                    .AsNoTracking()
                    .ToListAsync();

                return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Retrieves a specific hotel by id
        /// </summary>
        /// <param name="id">The hotel id</param>
        /// <returns>The hotel details</returns>
        /// <response code="200">Returns the requested hotel</response>
        /// <response code="404">If the hotel is not found</response>
        [HttpGet("{id}")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(HotelDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            try
            {
                var hotel = await _context.Hotels
                    .Include(h => h.Country)
                    .AsNoTracking()
                    .SingleOrDefaultAsync(h => h.Id == id);

                if (hotel == null)
                    return NotFound();

                return Ok(_mapper.Map<HotelDto>(hotel));
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Creates a new hotel
        /// </summary>
        /// <param name="hotelDto">The hotel data</param>
        /// <returns>The created hotel</returns>
        /// <response code="201">Returns the newly created hotel</response>
        /// <response code="400">If the hotel data is invalid</response>
        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(typeof(HotelDto), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<HotelDto>> CreateHotel([FromBody] HotelDto hotelDto)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var hotel = _mapper.Map<Hotel>(hotelDto);

                await _context.Hotels.AddAsync(hotel);
                await _context.SaveChangesAsync();

                hotelDto.Id = hotel.Id;

                return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Updates an existing hotel
        /// </summary>
        /// <param name="id">The hotel id</param>
        /// <param name="hotelDto">The updated hotel data</param>
        /// <returns>No content if successful</returns>
        /// <response code="204">If the hotel was successfully updated</response>
        /// <response code="400">If the hotel data is invalid</response>
        /// <response code="404">If the hotel is not found</response>
        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UpdateHotel(int id, [FromBody] HotelDto hotelDto)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var hotelInDb = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

                if (hotelInDb == null)
                    return NotFound();

                _mapper.Map(hotelDto, hotelInDb);
                await _context.SaveChangesAsync();

                return NoContent();
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }

        /// <summary>
        /// Deletes a specific hotel
        /// </summary>
        /// <param name="id">The hotel id</param>
        /// <returns>No content if successful</returns>
        /// <response code="204">If the hotel was successfully deleted</response>
        /// <response code="404">If the hotel is not found</response>
        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeleteHotel(int id)
        {
            try
            {
                var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

                if (hotel == null)
                    return NotFound();

                _context.Hotels.Remove(hotel);
                await _context.SaveChangesAsync();

                return NoContent();
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }
    }
}