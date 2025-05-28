using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;
using new_app.ViewModels;
using System.Linq;
using System.Threading.Tasks;

namespace new_app.Controllers
{
    public class HotelsController : Controller
    {
        private readonly ApplicationDbContext _context;

        // Inject the database context through constructor
        public HotelsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // No need for Dispose method as ASP.NET Core handles service disposal

        [AllowAnonymous]
        public async Task<IActionResult> Index()
        {
            if (User.IsInRole(RoleName.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> New()
        {
            var countries = await _context.Countries.ToListAsync();

            var viewModel = new HotelViewModel()
            {
                Hotel = new Hotel(),
                Countries = countries
            };

            return View("Form", viewModel);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
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
        [Authorize(Roles = RoleName.CanManageHotels)]
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
                // Update entity using model binding
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

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult NewCountry()
        {
            var country = new Country();

            return View("NewCountryForm", country);
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
}