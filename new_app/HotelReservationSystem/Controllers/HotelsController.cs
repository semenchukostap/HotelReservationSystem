using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers;

public class HotelsController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<HotelsController> _logger;

    public HotelsController(ApplicationDbContext context, ILogger<HotelsController> logger)
    {
        _context = context;
        _logger = logger;
    }

    [AllowAnonymous]
    public async Task<IActionResult> Index()
    {
        _logger.LogInformation("Accessing hotels index page");
        
        if (User.IsInRole(RoleConstants.Admin) || User.IsInRole(RoleConstants.HotelManager))
            return View("List");

        return View("ReadOnlyList");
    }

    [Authorize(Policy = "CanManageHotels")]
    public async Task<IActionResult> New()
    {
        _logger.LogInformation("Creating new hotel");
        
        var countries = await _context.Countries.ToListAsync();
        _logger.LogDebug("Retrieved {Count} countries for hotel form", countries.Count);

        var viewModel = new HotelViewModel
        {
            Hotel = new Hotel(),
            Countries = countries
        };

        return View("Form", viewModel);
    }

    [Authorize(Policy = "CanManageHotels")]
    public async Task<IActionResult> Edit(int id)
    {
        _logger.LogInformation("Editing hotel with ID: {HotelId}", id);
        
        var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
        {
            _logger.LogWarning("Hotel with ID: {HotelId} not found", id);
            return NotFound();
        }

        var viewModel = new HotelViewModel
        {
            Hotel = hotel,
            Countries = await _context.Countries.ToListAsync()
        };

        return View("Form", viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "CanManageHotels")]
    public async Task<IActionResult> Save(Hotel hotel)
    {
        _logger.LogInformation("Saving hotel with ID: {HotelId}", hotel.Id);
        
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Invalid hotel model state");
            
            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
            };

            return View("Form", viewModel);
        }

        try
        {
            if (hotel.Id == 0)
            {
                _logger.LogInformation("Adding new hotel: {HotelName}", hotel.Name);
                _context.Hotels.Add(hotel);
            }
            else
            {
                _logger.LogInformation("Updating existing hotel: {HotelName}", hotel.Name);
                var hotelInDb = await _context.Hotels.SingleAsync(c => c.Id == hotel.Id);
                hotelInDb.Name = hotel.Name;
                hotelInDb.City = hotel.City;
                hotelInDb.CountryId = hotel.CountryId;
                hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
                hotelInDb.PricePerNight = hotel.PricePerNight;
                hotelInDb.Stars = hotel.Stars;
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Successfully saved hotel");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving hotel");
            return StatusCode(500, "An error occurred while saving the hotel");
        }

        return RedirectToAction("Index", "Hotels");
    }

    public IActionResult NewCountry()
    {
        _logger.LogInformation("Creating new country");
        var country = new Country();

        return View("NewCountryForm", country);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "CanManageHotels")]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        _logger.LogInformation("Saving country: {CountryName}", country.Name);
        
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Invalid country model state");
            return View("NewCountryForm", country);
        }

        try
        {
            if (country.Id == 0)
            {
                _logger.LogInformation("Adding new country");
                _context.Countries.Add(country);
            }
            else
            {
                _logger.LogInformation("Updating existing country");
                var countryInDb = await _context.Countries.SingleAsync(c => c.Id == country.Id);
                countryInDb.Name = country.Name;
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("Successfully saved country");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving country");
            return StatusCode(500, "An error occurred while saving the country");
        }

        return RedirectToAction("New", "Hotels");
    }
}
