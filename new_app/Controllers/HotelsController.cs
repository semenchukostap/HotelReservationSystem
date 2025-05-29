using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers;

[ApiController]
[Route("[controller]")]
public class HotelsController : Controller
{
    private readonly IHotelService _hotelService;
    private readonly IMapper _mapper;
    private readonly ILogger<HotelsController> _logger;

    public HotelsController(
        IHotelService hotelService,
        IMapper mapper,
        ILogger<HotelsController> logger)
    {
        _hotelService = hotelService ?? throw new ArgumentNullException(nameof(hotelService));
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Index()
    {
        try
        {
            _logger.LogInformation("Accessing hotels index page");
            
            if (User.IsInRole(RoleName.CanManageHotels))
            {
                _logger.LogDebug("User has management privileges, showing full list view");
                return View("List");
            }

            _logger.LogDebug("User has read-only privileges, showing limited list view");
            return View("ReadOnlyList");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception occurred while accessing index page");
            return StatusCode(500, "An unexpected error occurred while processing your request.");
        }
    }

    [HttpGet("new")]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> New()
    {
        try
        {
            _logger.LogInformation("Creating new hotel form");
            var countries = await _hotelService.GetCountriesAsync();
            var viewModel = new HotelViewModel
            {
                Hotel = new Hotel(),
                Countries = countries
            };

            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while preparing new hotel form");
            return StatusCode(500, "An unexpected error occurred while processing your request.");
        }
    }

    [HttpGet("edit/{id}")]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
    {
        try
        {
            _logger.LogInformation("Editing hotel with ID: {HotelId}", id);
            
            var hotel = await _hotelService.GetByIdAsync(id);
            if (hotel == null)
            {
                _logger.LogWarning("Hotel with ID {HotelId} not found", id);
                return NotFound($"Hotel with ID {id} was not found.");
            }

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _hotelService.GetCountriesAsync()
            };

            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while editing hotel {HotelId}", id);
            return StatusCode(500, "An unexpected error occurred while processing your request.");
        }
    }

    [HttpPost("save")]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.CanManageHotels)]
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
                    Countries = await _hotelService.GetCountriesAsync()
                };
                return View("Form", viewModel);
            }

            if (hotel.Id == 0)
            {
                _logger.LogInformation("Creating new hotel: {HotelName}", hotel.Name);
                await _hotelService.CreateAsync(hotel);
            }
            else
            {
                _logger.LogInformation("Updating existing hotel: {HotelId}", hotel.Id);
                await _hotelService.UpdateAsync(hotel);
            }

            return RedirectToAction(nameof(Index));
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database error occurred while saving hotel {HotelId}", hotel.Id);
            return StatusCode(500, "A database error occurred while saving the hotel.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving hotel {HotelId}", hotel.Id);
            return StatusCode(500, "An unexpected error occurred while processing your request.");
        }
    }

    [HttpGet("country/new")]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public IActionResult NewCountry()
    {
        try
        {
            _logger.LogInformation("Accessing new country form");
            return View("NewCountryForm", new Country());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while accessing new country form");
            return StatusCode(500, "An unexpected error occurred while processing your request.");
        }
    }

    [HttpPost("country/save")]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.CanManageHotels)]
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
                _logger.LogInformation("Creating new country: {CountryName}", country.Name);
                await _hotelService.CreateCountryAsync(country);
            }
            else
            {
                _logger.LogInformation("Updating existing country: {CountryId}", country.Id);
                await _hotelService.UpdateCountryAsync(country);
            }

            return RedirectToAction(nameof(New));
        }
        catch (DbUpdateException dbEx)
        {
            _logger.LogError(dbEx, "Database error occurred while saving country {CountryId}", country.Id);
            return StatusCode(500, "A database error occurred while saving the country.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving country {CountryId}", country.Id);
            return StatusCode(500, "An unexpected error occurred while processing your request.");
        }
    }
}