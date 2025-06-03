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

        public HotelsController(ApplicationDbContext context)
        {
            _context = context;
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

        [Authorize(Policy = "RequireHotelManagerRole")]
        public async Task<IActionResult> Form(int? id)
        {
            ViewBag.Countries = await _context.Countries.ToListAsync();

            if (id == null)
                return View(new HotelViewModel());

            var hotel = await _context.Hotels.FindAsync(id);
            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel
            {
                Id = hotel.Id,
                Name = hotel.Name,
                City = hotel.City,
                CountryId = hotel.CountryId,
                Stars = hotel.Stars,
                PricePerNight = hotel.PricePerNight,
                IsAllInclusive = hotel.IsAllInclusive
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "RequireHotelManagerRole")]
        public async Task<IActionResult> Save(HotelViewModel viewModel)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Countries = await _context.Countries.ToListAsync();
                return View("Form", viewModel);
            }

            if (viewModel.Id == null)
            {
                var hotel = new Hotel
                {
                    Name = viewModel.Name,
                    City = viewModel.City,
                    CountryId = viewModel.CountryId,
                    Stars = viewModel.Stars,
                    PricePerNight = viewModel.PricePerNight,
                    IsAllInclusive = viewModel.IsAllInclusive
                };

                _context.Hotels.Add(hotel);
            }
            else
            {
                var hotel = await _context.Hotels.FindAsync(viewModel.Id);
                if (hotel == null)
                    return NotFound();

                hotel.Name = viewModel.Name;
                hotel.City = viewModel.City;
                hotel.CountryId = viewModel.CountryId;
                hotel.Stars = viewModel.Stars;
                hotel.PricePerNight = viewModel.PricePerNight;
                hotel.IsAllInclusive = viewModel.IsAllInclusive;
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(List));
        }

        [Authorize(Policy = "RequireHotelManagerRole")]
        public IActionResult NewCountryForm()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "RequireHotelManagerRole")]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
                return View("NewCountryForm", country);

            _context.Countries.Add(country);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Form));
        }
    }
}