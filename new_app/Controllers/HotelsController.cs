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
            var viewModel = new HotelViewModel
            {
                Countries = await _context.Countries.ToListAsync()
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

            Hotel hotel;
            
            if (viewModel.Id == 0)
            {
                hotel = new Hotel();
                _context.Hotels.Add(hotel);
            }
            else
            {
                hotel = await _context.Hotels.FindAsync(viewModel.Id);
                
                if (hotel == null)
                    return NotFound();
            }
            
            // Map viewModel to entity
            hotel.Name = viewModel.Name;
            hotel.City = viewModel.City;
            hotel.CountryId = viewModel.CountryId;
            hotel.IsAllInclusive = viewModel.IsAllInclusive;
            hotel.PricePerNight = viewModel.PricePerNight;
            hotel.Stars = viewModel.Stars;

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(List));
        }

        [Authorize(Roles = RoleName.Admin)]
        public IActionResult NewCountry()
        {
            return View("NewCountryForm", new Country());
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
                var countryInDb = await _context.Countries.FindAsync(country.Id);
                if (countryInDb != null)
                {
                    countryInDb.Name = country.Name;
                }
            }

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Form));
        }
    }
}
