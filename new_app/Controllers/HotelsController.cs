using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AutoMapper;
using HotelReservationSystem.Web.Services;
using HotelReservationSystem.Web.Models;
using HotelReservationSystem.Web.ViewModels;

namespace HotelReservationSystem.Web.Controllers;

public class HotelsController : Controller
{
    private readonly IHotelService _hotelService;
    private readonly IMapper _mapper;
    
    public HotelsController(IHotelService hotelService, IMapper mapper)
    {
        _hotelService = hotelService;
        _mapper = mapper;
    }

    [AllowAnonymous]
    public async Task<IActionResult> Index()
    {
        if (User.IsInRole(RoleName.CanManageHotels))
            return View("List", await _hotelService.GetAllAsync());

        return View("ReadOnlyList", await _hotelService.GetAllAsync());
    }

    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> Create()
    {
        var viewModel = new HotelViewModel
        {
            Hotel = new Hotel(),
            Countries = await _hotelService.GetCountriesAsync()
        };

        return View("Form", viewModel);
    }

    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
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

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> Save(Hotel hotel)
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

    [Authorize(Roles = RoleName.CanManageHotels)]
    public IActionResult NewCountry()
    {
        return View("NewCountryForm", new Country());
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.CanManageHotels)]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        if (!ModelState.IsValid)
            return View("NewCountryForm", country);

        if (country.Id == 0)
            await _hotelService.CreateCountryAsync(country);
        else
            await _hotelService.UpdateCountryAsync(country);

        return RedirectToAction(nameof(Create));
    }
}