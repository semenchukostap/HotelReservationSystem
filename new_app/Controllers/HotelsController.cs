using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers
{
    public class HotelsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<HotelsController> _logger;

        public HotelsController(ApplicationDbContext context, ILogger<HotelsController> logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public IActionResult Index()
        {
            if (User.IsInRole(RoleName.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }

        public async Task<IActionResult> List()
        {
            try
            {
                var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
                return View(hotels);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving hotel list");
                return StatusCode(500, "An error occurred while retrieving the hotel list");
            }
        }

        public async Task<IActionResult> ReadOnlyList()
        {
            try
            {
                var hotels = await _context.Hotels.Include(h => h.Country).ToListAsync();
                return View(hotels);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving read-only hotel list");
                return StatusCode(500, "An error occurred while retrieving the hotel list");
            }
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> New()
        {
            try
            {
                var countries = await _context.Countries.ToListAsync();

                var viewModel = new HotelViewModel
                {
                    Hotel = new Hotel(),
                    Countries = countries
                };

                return View("Form", viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating new hotel form");
                return StatusCode(500, "An error occurred while preparing the hotel form");
            }
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Edit(int id)
        {
            try
            {
                var hotel = await _context.Hotels.FindAsync(id);

                if (hotel == null)
                {
                    _logger.LogWarning("Hotel with ID {HotelId} not found", id);
                    return NotFound();
                }

                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _context.Countries.ToListAsync()
                };

                return View("Form", viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error editing hotel with ID {HotelId}", id);
                return StatusCode(500, "An error occurred while retrieving the hotel data");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Save(Hotel hotel)
        {
            try
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
                    await _context.Hotels.AddAsync(hotel);
                    _logger.LogInformation("New hotel added: {HotelName}", hotel.Name);
                }
                else
                {
                    var hotelInDb = await _context.Hotels.FindAsync(hotel.Id);
                    
                    if (hotelInDb == null)
                    {
                        _logger.LogWarning("Hotel with ID {HotelId} not found during save operation", hotel.Id);
                        return NotFound();
                    }
                        
                    hotelInDb.Name = hotel.Name;
                    hotelInDb.City = hotel.City;
                    hotelInDb.CountryId = hotel.CountryId;
                    hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
                    hotelInDb.PricePerNight = hotel.PricePerNight;
                    hotelInDb.Stars = hotel.Stars;
                    
                    _logger.LogInformation("Hotel updated: {HotelName} (ID: {HotelId})", hotel.Name, hotel.Id);
                }

                await _context.SaveChangesAsync();

                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving hotel {HotelName} (ID: {HotelId})", hotel.Name, hotel.Id);
                ModelState.AddModelError("", "An error occurred while saving the hotel.");
                
                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _context.Countries.ToListAsync()
                };
                
                return View("Form", viewModel);
            }
        }

        public IActionResult NewCountry()
        {
            return View("NewCountryForm", new Country());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View("NewCountryForm", country);
                }

                if (country.Id == 0)
                {
                    await _context.Countries.AddAsync(country);
                    _logger.LogInformation("New country added: {CountryName}", country.Name);
                }
                else
                {
                    var countryInDb = await _context.Countries.FindAsync(country.Id);
                    
                    if (countryInDb == null)
                    {
                        _logger.LogWarning("Country with ID {CountryId} not found during save operation", country.Id);
                        return NotFound();
                    }
                        
                    countryInDb.Name = country.Name;
                    _logger.LogInformation("Country updated: {CountryName} (ID: {CountryId})", country.Name, country.Id);
                }

                await _context.SaveChangesAsync();

                return RedirectToAction(nameof(New));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving country {CountryName} (ID: {CountryId})", country.Name, country.Id);
                ModelState.AddModelError("", "An error occurred while saving the country.");
                return View("NewCountryForm", country);
            }
        }
    }
}
