using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;

namespace HotelReservationSystem.Controllers
{
    public class HotelsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public HotelsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: Hotels
        public async Task<IActionResult> Index()
        {
            if (User.IsInRole(RoleName.Admin))
                return View("List", await _context.Hotels.Include(h => h.Country).ToListAsync());

            return View("ReadOnlyList", await _context.Hotels.Include(h => h.Country).ToListAsync());
        }

        // GET: Hotels/New
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> New()
        {
            var viewModel = new HotelViewModel
            {
                Countries = await _context.Countries.ToListAsync(),
                Hotel = new Hotel()
            };

            return View("Form", viewModel);
        }

        // GET: Hotels/Edit/5
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> Edit(int id)
        {
            var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
            };

            return View("Form", viewModel);
        }

        // POST: Hotels/Save
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.Admin)]
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
                _context.Hotels.Add(hotel);
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
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        // GET: Hotels/NewCountry
        [Authorize(Roles = RoleName.Admin)]
        public IActionResult NewCountry()
        {
            return View("NewCountryForm", new Country());
        }

        // POST: Hotels/SaveCountry
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
                return View("NewCountryForm", country);

            if (country.Id == 0)
                _context.Countries.Add(country);
            else
            {
                var countryInDb = await _context.Countries.FindAsync(country.Id);
                if (countryInDb == null)
                    return NotFound();
                    
                countryInDb.Name = country.Name;
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(New));
        }
        
        // GET: Hotels/List
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> List()
        {
            return View(await _context.Hotels.Include(h => h.Country).ToListAsync());
        }
        
        // GET: Hotels/ReadOnlyList
        public async Task<IActionResult> ReadOnlyList()
        {
            return View(await _context.Hotels.Include(h => h.Country).ToListAsync());
        }
    }
}