using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Controllers;

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

    [AllowAnonymous]
    public async Task<IActionResult> Index()
    {
        try
        {
            if (User.IsInRole(RoleName.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while processing Index action");
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }

    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> New()
    {
        try
        {
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
            _logger.LogError(ex, "Error occurred while processing New action");
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }

    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
    {
        try
        {
            var hotel = await _hotelService.GetByIdAsync(id);
            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _hotelService.GetCountriesAsync()
            };

            return View("Form", viewModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while processing Edit action for hotel {HotelId}", id);
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> Save(Hotel hotel)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _hotelService.GetCountriesAsync()
                };
                return View("Form", viewModel);
            }

            if (hotel.Id == 0)
                await _hotelService.CreateAsync(hotel);
            else
                await _hotelService.UpdateAsync(hotel);

            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving hotel {HotelId}", hotel.Id);
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }

    [Authorize(Roles = RoleName.CanManageHotels)]
    public IActionResult NewCountry()
    {
        try
        {
            return View("NewCountryForm", new Country());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while processing NewCountry action");
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        try
        {
            if (!ModelState.IsValid)
                return View("NewCountryForm", country);

            if (country.Id == 0)
                await _hotelService.CreateCountryAsync(country);
            else
                await _hotelService.UpdateCountryAsync(country);

            return RedirectToAction(nameof(New));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while saving country {CountryId}", country.Id);
            return StatusCode(500, "An error occurred while processing your request.");
        }
    }
}