using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq;

namespace HotelReservationSystem.Controllers.Api
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
        public IActionResult GetHotels()
        {
            var hotels = _context.Hotels
                .Include(c => c.Country)
                .ToList();
            
            return Ok(_mapper.Map<IEnumerable<HotelDto>>(hotels));
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public IActionResult GetHotel(int id)
        {
            var hotel = _context.Hotels
                .Include(h => h.Country)
                .SingleOrDefault(c => c.Id == id);

            if (hotel == null)
                return NotFound();

            return Ok(_mapper.Map<HotelDto>(hotel));
        }

        [HttpPost]
        [Authorize(Policy = "CanManageHotels")]
        public IActionResult CreateHotel(HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var hotel = _mapper.Map<Hotel>(hotelDto);

            _context.Hotels.Add(hotel);
            _context.SaveChanges();

            hotelDto.Id = hotel.Id;

            return CreatedAtAction(nameof(GetHotel), new { id = hotel.Id }, hotelDto);
        }

        [HttpPut("{id}")]
        [Authorize(Policy = "CanManageHotels")]
        public IActionResult UpdateHotel(int id, HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var hotelInDb = _context.Hotels.SingleOrDefault(c => c.Id == id);

            if (hotelInDb == null)
                return NotFound();
                
            _mapper.Map(hotelDto, hotelInDb);

            _context.SaveChanges();
            
            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "CanManageHotels")]
        public IActionResult DeleteHotel(int id)
        {
            var hotel = _context.Hotels.SingleOrDefault(c => c.Id == id);

            if (hotel == null)
                return NotFound();

            _context.Hotels.Remove(hotel);
            _context.SaveChanges();
            
            return NoContent();
        }
    }
}