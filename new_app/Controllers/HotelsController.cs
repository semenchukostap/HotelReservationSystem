using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using HotelReservationSystem.Constants;

namespace HotelReservationSystem.Controllers;

public class HotelsController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<HotelsController> _logger;
    
    public HotelsController(ApplicationDbContext context, ILogger<HotelsController> logger)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    [AllowAnonymous]
    public IActionResult Index()
    {
        try
        {
            if (User.IsInRole(RoleNames.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while accessing the index page");
            return StatusCode(500, "An unexpected error occurred");
        }
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> New()
    {
        try
        {
            var countries = await _context.Countries.ToListAsync();

            var viewModel = new HotelViewModel
            {
                Hotel = new Hotel(),
                Countries = countries
            };

            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while creating new hotel form");
            return StatusCode(500, "An unexpected error occurred");
        }
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
    {
        try
        {
            var hotel = await _context.Hotels
                .AsNoTracking()
                .SingleOrDefaultAsync(h => h.Id == id);

            if (hotel == null)
            {
                _logger.LogWarning("Hotel with ID {HotelId} not found", id);
                return NotFound();
            }

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
            };

            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while editing hotel with ID {HotelId}", id);
            return StatusCode(500, "An unexpected error occurred");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Save(Hotel hotel)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _context.Countries.ToListAsync()
                };

                return View("Form", viewModel);
            }

            if (hotel.Id == 0)
            {
                await _context.Hotels.AddAsync(hotel);
                _logger.LogInformation("Created new hotel: {HotelName}", hotel.Name);
            }
            else
            {
                var hotelInDb = await _context.Hotels.SingleAsync(c => c.Id == hotel.Id);
                hotelInDb.Name = hotel.Name;
                hotelInDb.City = hotel.City;
                hotelInDb.CountryId = hotel.CountryId;
                hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
                hotelInDb.PricePerNight = hotel.PricePerNight;
                hotelInDb.Stars = hotel.Stars;
                _logger.LogInformation("Updated hotel with ID {HotelId}", hotel.Id);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error occurred while saving hotel");
            ModelState.AddModelError("", "Unable to save changes. Please try again.");
            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
            };
            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while saving hotel");
            return StatusCode(500, "An unexpected error occurred");
        }
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public IActionResult NewCountry()
    {
        try
        {
            return View("NewCountryForm", new Country());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while creating new country form");
            return StatusCode(500, "An unexpected error occurred");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return View("NewCountryForm", country);
            }

            if (country.Id == 0)
            {
                await _context.Countries.AddAsync(country);
                _logger.LogInformation("Created new country: {CountryName}", country.Name);
            }
            else
            {
                var countryInDb = await _context.Countries.SingleAsync(c => c.Id == country.Id);
                countryInDb.Name = country.Name;
                _logger.LogInformation("Updated country with ID {CountryId}", country.Id);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(New));
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Error occurred while saving country");
            ModelState.AddModelError("", "Unable to save changes. Please try again.");
            return View("NewCountryForm", country);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while saving country");
            return StatusCode(500, "An unexpected error occurred");
        }
    }
}