using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class HotelsController : ControllerBase
    {
        private readonly IHotelService _hotelService;
        private readonly IMapper _mapper;

        public HotelsController(IHotelService hotelService, IMapper mapper)
        {
            _hotelService = hotelService;
            _mapper = mapper;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
        {
            var hotels = await _hotelService.GetAllHotelDtosAsync();
            return Ok(hotels);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<ActionResult<HotelDto>> GetHotel(int id)
        {
            var hotel = await _hotelService.GetHotelByIdAsync(id);

            if (hotel == null)
                return NotFound();

            return Ok(_mapper.Map<HotelDto>(hotel));
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<HotelDto>> CreateHotel(HotelDto hotelDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var hotel = _mapper.Map<Hotel>(hotelDto);

            var id = await _hotelService.CreateHotelAsync(hotel);
            hotelDto.Id = id;

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

            var hotel = await _hotelService.GetHotelByIdAsync(id);

            if (hotel == null)
                return NotFound();

            _mapper.Map(hotelDto, hotel);

            await _hotelService.UpdateHotelAsync(hotel);

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> DeleteHotel(int id)
        {
            var hotel = await _hotelService.GetHotelByIdAsync(id);
            if (hotel == null)
                return NotFound();

            await _hotelService.DeleteHotelAsync(id);

            return NoContent();
        }
    }
}