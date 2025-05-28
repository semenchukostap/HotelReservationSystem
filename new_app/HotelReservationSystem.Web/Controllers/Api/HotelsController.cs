using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;
using HotelReservationSystem.Core.Constants;

namespace HotelReservationSystem.Web.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    public class HotelsController : ControllerBase
    {
        private readonly IHotelService _hotelService;
        
        public HotelsController(IHotelService hotelService)
        {
            _hotelService = hotelService;
        }
        
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _hotelService.GetAllHotelsAsync();
            return Ok(hotels);
        }
        
        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _hotelService.GetHotelByIdAsync(id);
            
            if (hotel == null)
                return NotFound();
                
            return Ok(hotel);
        }
        
        [HttpPost]
        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            var createdHotel = await _hotelService.CreateHotelAsync(hotelDto);
            
            return CreatedAtAction(nameof(GetHotel), new { id = createdHotel.Id }, createdHotel);
        }
        
        [HttpPut("{id}")]
        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            await _hotelService.UpdateHotelAsync(id, hotelDto);
            
            return NoContent();
        }
        
        [HttpDelete("{id}")]
        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<IActionResult> DeleteHotel(int id)
        {
            await _hotelService.DeleteHotelAsync(id);
            
            return NoContent();
        }
    }
}