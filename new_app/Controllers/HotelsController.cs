using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;
using new_app.ViewModels;

namespace new_app.Controllers
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

        [AllowAnonymous]
        public IActionResult Index()
        {
            if (User.IsInRole(RoleName.Admin))
                return RedirectToAction("List");

            return RedirectToAction("ReadOnlyList");
        }

        // GET: Hotels/List
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> List()
        {
            var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
            return View(hotels);
        }

        // GET: Hotels/ReadOnlyList
        [AllowAnonymous]
        public async Task<IActionResult> ReadOnlyList()
        {
            var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
            return View(hotels);
        }

        // GET: Hotels/Form
        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> Form(int? id)
        {
            var viewModel = new HotelViewModel
            {
                Countries = await _context.Countries.ToListAsync()
            };

            if (id == null)
            {
                // Initialize empty hotel properties
                viewModel.Id = 0;
                viewModel.Name = string.Empty;
                viewModel.City = string.Empty;
                viewModel.CountryId = 0;
                viewModel.IsAllInclusive = false;
                viewModel.PricePerNight = 0;
                viewModel.Stars = 0;
                return View(viewModel);
            }
            
            var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);
            
            if (hotel == null)
                return NotFound();
            
            // Map hotel properties to viewModel
            viewModel.Id = hotel.Id;
            viewModel.Name = hotel.Name;
            viewModel.City = hotel.City;
            viewModel.CountryId = hotel.CountryId;
            viewModel.IsAllInclusive = hotel.IsAllInclusive;
            viewModel.PricePerNight = hotel.PricePerNight;
            viewModel.Stars = hotel.Stars;
            
            return View(viewModel);
        }

        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> New()
        {
            var countries = await _context.Countries.ToListAsync();

            var viewModel = new HotelViewModel()
            {
                Id = 0,
                Name = string.Empty,
                City = string.Empty,
                CountryId = 0,
                IsAllInclusive = false,
                PricePerNight = 0,
                Stars = 0,
                Countries = countries
            };

            return View("Form", viewModel);
        }

        [Authorize(Roles = RoleName.Admin)]
        public async Task<IActionResult> Edit(int id)
        {
            var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == id);

            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel()
            {
                Id = hotel.Id,
                Name = hotel.Name,
                City = hotel.City,
                CountryId = hotel.CountryId,
                IsAllInclusive = hotel.IsAllInclusive,
                PricePerNight = hotel.PricePerNight,
                Stars = hotel.Stars,
                Countries = await _context.Countries.ToListAsync()
            };

            return View("Form", viewModel);
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

            var hotel = new Hotel
            {
                Id = viewModel.Id,
                Name = viewModel.Name,
                City = viewModel.City,
                CountryId = viewModel.CountryId,
                IsAllInclusive = viewModel.IsAllInclusive,
                PricePerNight = viewModel.PricePerNight,
                Stars = viewModel.Stars
            };

            if (hotel.Id == 0)
                _context.Hotels.Add(hotel);
            else
            {
                var hotelInDb = await _context.Hotels.SingleOrDefaultAsync(c => c.Id == hotel.Id);
                
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

            return RedirectToAction("List");
        }

        [Authorize(Roles = RoleName.Admin)]
        public IActionResult NewCountry()
        {
            var country = new Country();

            return View("NewCountryForm", country);
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
            {
                return View("NewCountryForm", country);
            }

            if (country.Id == 0)
                _context.Countries.Add(country);
            else
            {
                var countryInDb = await _context.Countries.SingleOrDefaultAsync(c => c.Id == country.Id);
                if (countryInDb != null)
                {
                    countryInDb.Name = country.Name;
                }
            }

            await _context.SaveChangesAsync();

            return RedirectToAction("Form");
        }
    }
}