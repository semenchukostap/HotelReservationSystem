using HotelReservationSystem.Core.Constants;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Services;
using HotelReservationSystem.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace HotelReservationSystem.Web.Controllers;

public class HotelsController : Controller
{
    private readonly IHotelService _hotelService;
    private readonly ICountryService _countryService;

    public HotelsController(IHotelService hotelService, ICountryService countryService)
    {
        _hotelService = hotelService;
        _countryService = countryService;
    }

    [AllowAnonymous]
    public IActionResult Index()
    {
        if (User.IsInRole(RoleNames.CanManageHotels))
            return View("List");

        return View("ReadOnlyList");
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> New()
    {
        var countries = await _countryService.GetAllCountriesAsync();

        var viewModel = new HotelViewModel
        {
            Hotel = new HotelDto(),
            Countries = countries
        };

        return View("Form", viewModel);
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
    {
        var hotel = await _hotelService.GetHotelByIdAsync(id);

        if (hotel == null)
            return NotFound();

        var viewModel = new HotelViewModel
        {
            Hotel = hotel,
            Countries = await _countryService.GetAllCountriesAsync()
        };

        return View("Form", viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Save(HotelDto hotel)
    {
        if (!ModelState.IsValid)
        {
            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _countryService.GetAllCountriesAsync()
            };

            return View("Form", viewModel);
        }

        if (hotel.Id == 0)
            await _hotelService.CreateHotelAsync(hotel);
        else
            await _hotelService.UpdateHotelAsync(hotel.Id, hotel);

        return RedirectToAction("Index");
    }
    
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public IActionResult NewCountry()
    {
        var country = new CountryDto();

        return View("NewCountryForm", country);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> SaveCountry(CountryDto country)
    {
        if (!ModelState.IsValid)
        {
            return View("NewCountryForm", country);
        }

        if (country.Id == 0)
            await _countryService.CreateCountryAsync(country);
        else
            await _countryService.UpdateCountryAsync(country.Id, country);

        return RedirectToAction("New");
    }
}