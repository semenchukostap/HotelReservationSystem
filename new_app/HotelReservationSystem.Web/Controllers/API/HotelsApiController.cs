using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Web.Controllers.API
{
    [Route("api/hotels")]
    [ApiController]
    public class HotelsApiController : ControllerBase
    {
        private readonly IHotelService _hotelService;

        public HotelsApiController(IHotelService hotelService)
        {
            _hotelService = hotelService;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetHotels()
        {
            var hotels = await _hotelService.GetAllHotelsAsync();
            return Ok(hotels);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetHotel(int id)
        {
            var hotel = await _hotelService.GetHotelByIdAsync(id);
            if (hotel == null)
                return NotFound();

            return Ok(hotel);
        }

        [HttpPost]
        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> CreateHotel(HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            await _hotelService.CreateHotelAsync(hotelDto);
            return CreatedAtAction(nameof(GetHotel), new { id = hotelDto.Id }, hotelDto);
        }

        [HttpPut("{id}")]
        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> UpdateHotel(int id, HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                await _hotelService.UpdateHotelAsync(id, hotelDto);
                return NoContent();
            }
            catch (KeyNotFoundException)
            {
                return NotFound();
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> DeleteHotel(int id)
        {
            try
            {
                await _hotelService.DeleteHotelAsync(id);
                return NoContent();
            }
            catch (KeyNotFoundException)
            {
                return NotFound();
            }
        }
    }
}