using HotelReservationSystem.Core.Constants;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Web.Controllers.Api;

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

        var id = await _hotelService.CreateHotelAsync(hotelDto);
        hotelDto.Id = id;

        return CreatedAtAction(nameof(GetHotel), new { id }, hotelDto);
    }

    [HttpPut("{id}")]
    [Authorize(Roles = RoleNames.CanManageHotels)]
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
    [Authorize(Roles = RoleNames.CanManageHotels)]
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