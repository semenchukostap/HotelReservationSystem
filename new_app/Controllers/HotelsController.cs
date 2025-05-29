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
    
    public HotelsController(
        ApplicationDbContext context,
        ILogger<HotelsController> logger)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    [AllowAnonymous]
    public IActionResult Index()
    {
        try
        {
            _logger.LogInformation("Accessing hotels index page");
            if (User.IsInRole(RoleNames.CanManageHotels))
            {
                _logger.LogDebug("User has management rights. Showing full list view");
                return View("List");
            }

            _logger.LogDebug("User has read-only rights. Showing limited view");
            return View("ReadOnlyList");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while accessing the index page");
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> New()
    {
        try
        {
            _logger.LogInformation("Creating new hotel form");
            var countries = await _context.Countries.AsNoTracking().ToListAsync();

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
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
    {
        try
        {
            _logger.LogInformation("Editing hotel with ID {HotelId}", id);
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
                Countries = await _context.Countries.AsNoTracking().ToListAsync()
            };

            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while editing hotel with ID {HotelId}", id);
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Save([FromForm] Hotel hotel)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state when saving hotel");
                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _context.Countries.AsNoTracking().ToListAsync()
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
                var hotelInDb = await _context.Hotels.FindAsync(hotel.Id);
                if (hotelInDb == null)
                {
                    _logger.LogWarning("Hotel with ID {HotelId} not found during update", hotel.Id);
                    return NotFound();
                }

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
            _logger.LogError(ex, "Database error occurred while saving hotel");
            ModelState.AddModelError("", "Unable to save changes. Please try again.");
            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.AsNoTracking().ToListAsync()
            };
            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while saving hotel");
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public IActionResult NewCountry()
    {
        try
        {
            _logger.LogInformation("Creating new country form");
            return View("NewCountryForm", new Country());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while creating new country form");
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> SaveCountry([FromForm] Country country)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid model state when saving country");
                return View("NewCountryForm", country);
            }

            if (country.Id == 0)
            {
                await _context.Countries.AddAsync(country);
                _logger.LogInformation("Created new country: {CountryName}", country.Name);
            }
            else
            {
                var countryInDb = await _context.Countries.FindAsync(country.Id);
                if (countryInDb == null)
                {
                    _logger.LogWarning("Country with ID {CountryId} not found during update", country.Id);
                    return NotFound();
                }

                countryInDb.Name = country.Name;
                _logger.LogInformation("Updated country with ID {CountryId}", country.Id);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(New));
        }
        catch (DbUpdateException ex)
        {
            _logger.LogError(ex, "Database error occurred while saving country");
            ModelState.AddModelError("", "Unable to save changes. Please try again.");
            return View("NewCountryForm", country);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error occurred while saving country");
            return StatusCode(StatusCodes.Status500InternalServerError, "An unexpected error occurred");
        }
    }
}