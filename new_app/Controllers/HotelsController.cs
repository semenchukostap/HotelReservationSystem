using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers;

public class HotelsController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<HotelsController> _logger;

    public HotelsController(
        ApplicationDbContext context,
        ILogger<HotelsController> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<IActionResult> List()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
        
        return View(hotels);
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Create()
    {
        var viewModel = new HotelViewModel
        {
            Countries = await GetCountriesSelectList()
        };

        return View("Form", viewModel);
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Edit(int id)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
        {
            return NotFound();
        }

        var viewModel = new HotelViewModel(hotel)
        {
            Countries = await GetCountriesSelectList()
        };

        return View("Form", viewModel);
    }

    [HttpPost]
    [Authorize(Roles = RoleName.Admin)]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(HotelViewModel viewModel)
    {
        if (!ModelState.IsValid)
        {
            viewModel.Countries = await GetCountriesSelectList();
            return View("Form", viewModel);
        }

        Hotel hotel;
        if (viewModel.Id == 0)
        {
            hotel = new Hotel();
            _context.Hotels.Add(hotel);
            _logger.LogInformation("New hotel created");
        }
        else
        {
            hotel = await _context.Hotels.FindAsync(viewModel.Id);
            if (hotel == null)
            {
                return NotFound();
            }
            _logger.LogInformation("Hotel updated: {HotelId}", hotel.Id);
        }

        // Map view model to entity
        hotel.Name = viewModel.Name;
        hotel.CountryId = viewModel.CountryId;
        hotel.City = viewModel.City;
        hotel.Stars = viewModel.Stars;
        hotel.PricePerNight = viewModel.PricePerNight;
        hotel.IsAllInclusive = viewModel.IsAllInclusive;

        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(List));
    }

    public async Task<IActionResult> ReadOnlyList()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return View(hotels);
    }

    [Authorize(Roles = RoleName.Admin)]
    public IActionResult NewCountryForm()
    {
        return View(new Country());
    }

    [HttpPost]
    [Authorize(Roles = RoleName.Admin)]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        if (!ModelState.IsValid)
        {
            return View("NewCountryForm", country);
        }

        if (country.Id == 0)
        {
            _context.Countries.Add(country);
            _logger.LogInformation("New country created");
        }
        else
        {
            _context.Entry(country).State = EntityState.Modified;
            _logger.LogInformation("Country updated: {CountryId}", country.Id);
        }

        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(Create));
    }

    private async Task<IEnumerable<SelectListItem>> GetCountriesSelectList()
    {
        var countries = await _context.Countries.ToListAsync();
        return countries.Select(c => new SelectListItem
        {
            Value = c.Id.ToString(),
            Text = c.Name
        });
    }
}