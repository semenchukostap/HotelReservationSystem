using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;

namespace new_app.Controllers.API;

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

    // GET: api/Hotels
    [HttpGet]
    public async Task<ActionResult<IEnumerable<HotelDto>>> GetHotels()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return _mapper.Map<List<HotelDto>>(hotels);
    }

    // GET: api/Hotels/5
    [HttpGet("{id}")]
    public async Task<ActionResult<HotelDto>> GetHotel(int id)
    {
        var hotel = await _context.Hotels
            .Include(h => h.Country)
            .SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
        {
            return NotFound();
        }

        return _mapper.Map<HotelDto>(hotel);
    }
}