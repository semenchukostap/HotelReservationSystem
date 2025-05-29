using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using HotelReservationSystem.Constants;

namespace HotelReservationSystem.Controllers;

public class HotelsController : Controller
{
    private readonly ApplicationDbContext _context;
    
    public HotelsController(ApplicationDbContext context)
    {
        _context = context;
    }

    [AllowAnonymous]
    public IActionResult Index()
    {
        if (User.IsInRole(RoleNames.CanManageHotels))
            return View("List");

        return View("ReadOnlyList");
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public IActionResult New()
    {
        var countries = _context.Countries.ToList();

        var viewModel = new HotelViewModel()
        {
            Hotel = new Hotel(),
            Countries = countries
        };

        return View("Form", viewModel);
    }

    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Edit(int id)
    {
        var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

        if (hotel == null)
            return NotFound();

        var viewModel = new HotelViewModel()
        {
            Hotel = hotel,
            Countries = await _context.Countries.ToListAsync()
        };

        return View("Form", viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> Save(Hotel hotel)
    {
        if (!ModelState.IsValid)
        {
            var viewModel = new HotelViewModel()
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
            };

            return View("Form", viewModel);
        }

        if (hotel.Id == 0)
            _context.Hotels.Add(hotel);
        else
        {
            var hotelInDb = await _context.Hotels.SingleAsync(c => c.Id == hotel.Id);
            hotelInDb.Name = hotel.Name;
            hotelInDb.City = hotel.City;
            hotelInDb.CountryId = hotel.CountryId;
            hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
            hotelInDb.PricePerNight = hotel.PricePerNight;
            hotelInDb.Stars = hotel.Stars;
        }

        await _context.SaveChangesAsync();

        return RedirectToAction("Index", "Hotels");
    }

    public IActionResult NewCountry()
    {
        var country = new Country();

        return View("NewCountryForm", country);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleNames.CanManageHotels)]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        if (!ModelState.IsValid)
        {
            return View("NewCountryForm", country);
        }

        if (country.Id == 0)
            _context.Countries.Add(country);
        else
        {
            var countryInDb = await _context.Countries.SingleAsync(c => c.Id == country.Id);
            countryInDb.Name = country.Name;
        }

        await _context.SaveChangesAsync();

        return RedirectToAction("New", "Hotels");
    }
}