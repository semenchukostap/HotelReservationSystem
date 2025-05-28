using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers
{
    public class HotelsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<HotelsController> _logger;

        public HotelsController(ApplicationDbContext context, ILogger<HotelsController> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            if (User.IsInRole(RoleName.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }

        public async Task<IActionResult> List()
        {
            var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
            return View(hotels);
        }

        public async Task<IActionResult> ReadOnlyList()
        {
            var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
            return View(hotels);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> New()
        {
            var countries = await _context.Countries.ToListAsync();

            var viewModel = new HotelViewModel
            {
                Hotel = new Hotel(),
                Countries = countries
            };

            return View("Form", viewModel);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Edit(int id)
        {
            var hotel = await _context.Hotels.FindAsync(id);

            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
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
                    Countries = await _context.Countries.ToListAsync()
                };

                return View("Form", viewModel);
            }

            if (hotel.Id == 0)
            {
                _context.Hotels.Add(hotel);
                _logger.LogInformation("New hotel added: {HotelName}", hotel.Name);
            }
            else
            {
                var hotelInDb = await _context.Hotels.FindAsync(hotel.Id);
                
                if (hotelInDb == null)
                    return NotFound();
                    
                hotelInDb.Name = hotel.Name;
                hotelInDb.City = hotel.City;
                hotelInDb.CountryId = hotel.CountryId;
                hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
                hotelInDb.PricePerNight = hotel.PricePerNight;
                hotelInDb.Stars = hotel.Stars;
                
                _logger.LogInformation("Hotel updated: {HotelName}", hotel.Name);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> NewCountry()
        {
            return View("NewCountryForm", new Country());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
            {
                return View("NewCountryForm", country);
            }

            if (country.Id == 0)
            {
                _context.Countries.Add(country);
                _logger.LogInformation("New country added: {CountryName}", country.Name);
            }
            else
            {
                var countryInDb = await _context.Countries.FindAsync(country.Id);
                
                if (countryInDb == null)
                    return NotFound();
                    
                countryInDb.Name = country.Name;
                _logger.LogInformation("Country updated: {CountryName}", country.Name);
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(New));
        }
    }
}