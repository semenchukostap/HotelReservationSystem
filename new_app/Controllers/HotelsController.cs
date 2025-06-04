using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;
using new_app.ViewModels;

namespace new_app.Controllers;

public class HotelsController : Controller
{
    private readonly ApplicationDbContext _context;

    public HotelsController(ApplicationDbContext context)
    {
        _context = context;
    }

    [AllowAnonymous]
    public async Task<IActionResult> List()
    {
        var hotels = await _context.Hotels
            .Include(h => h.Country)
            .ToListAsync();
            
        return View(hotels);
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Form(int id = 0)
    {
        if (id == 0)
        {
            // New hotel form
            var viewModel = new HotelViewModel
            {
                Countries = await _context.Countries.ToListAsync()
            };
            
            return View(viewModel);
        }
        else
        {
            // Edit hotel form
            var hotel = await _context.Hotels.FindAsync(id);
            
            if (hotel == null)
                return NotFound();
                
            var viewModel = new HotelViewModel
            {
                Id = hotel.Id,
                Name = hotel.Name,
                CountryId = hotel.CountryId,
                City = hotel.City,
                Stars = hotel.Stars,
                PricePerNight = hotel.PricePerNight,
                IsAllInclusive = hotel.IsAllInclusive,
                Countries = await _context.Countries.ToListAsync()
            };
            
            return View(viewModel);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Save(HotelViewModel viewModel)
    {
        if (!ModelState.IsValid)
        {
            viewModel.Countries = await _context.Countries.ToListAsync();
            return View("Form", viewModel);
        }

        if (viewModel.Id == 0)
        {
            // New hotel
            var hotel = new Hotel
            {
                Name = viewModel.Name,
                CountryId = viewModel.CountryId,
                City = viewModel.City,
                Stars = viewModel.Stars,
                PricePerNight = viewModel.PricePerNight,
                IsAllInclusive = viewModel.IsAllInclusive
            };
            
            await _context.Hotels.AddAsync(hotel);
        }
        else
        {
            // Update existing hotel
            var hotel = await _context.Hotels.FindAsync(viewModel.Id);
            
            if (hotel == null)
                return NotFound();
                
            hotel.Name = viewModel.Name;
            hotel.CountryId = viewModel.CountryId;
            hotel.City = viewModel.City;
            hotel.Stars = viewModel.Stars;
            hotel.PricePerNight = viewModel.PricePerNight;
            hotel.IsAllInclusive = viewModel.IsAllInclusive;
        }
        
        await _context.SaveChangesAsync();
        
        return RedirectToAction(nameof(List));
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Delete(int id)
    {
        var hotel = await _context.Hotels.FindAsync(id);
        
        if (hotel == null)
            return NotFound();
            
        _context.Hotels.Remove(hotel);
        await _context.SaveChangesAsync();
        
        return RedirectToAction(nameof(List));
    }

    [AllowAnonymous]
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
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> SaveCountry(Country country)
    {
        if (!ModelState.IsValid)
            return View("NewCountryForm", country);

        await _context.Countries.AddAsync(country);
        await _context.SaveChangesAsync();
        
        return RedirectToAction(nameof(Form));
    }
}