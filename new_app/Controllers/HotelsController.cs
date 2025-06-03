using AutoMapper;
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

        public HotelsController(ApplicationDbContext context)
        {
            _context = context;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            if (User.IsInRole(RoleName.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }

        [Authorize(Policy = "CanManageHotels")]
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

        [Authorize(Policy = "CanManageHotels")]
        public IActionResult Edit(int id)
        {
            var hotel = _context.Hotels.SingleOrDefault(h => h.Id == id);

            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel()
            {
                Hotel = hotel,
                Countries = _context.Countries.ToList()
            };

            return View("Form", viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "CanManageHotels")]
        public IActionResult Save(Hotel hotel)
        {
            if(!ModelState.IsValid)
            {
                var viewModel = new HotelViewModel()
                {
                    Hotel = hotel,
                    Countries = _context.Countries.ToList()
                };

                return View("Form", viewModel);
            }

            if (hotel.Id == 0)
                _context.Hotels.Add(hotel);
            else
            {
                var hotelInDb = _context.Hotels.Single(c => c.Id == hotel.Id);
                hotelInDb.Name = hotel.Name;
                hotelInDb.City = hotel.City;
                hotelInDb.CountryId = hotel.CountryId;
                hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
                hotelInDb.PricePerNight = hotel.PricePerNight;
                hotelInDb.Stars = hotel.Stars;
            }

            _context.SaveChanges();

            return RedirectToAction("Index", "Hotels");
        }

        public IActionResult NewCountry()
        {
            var country = new Country();

            return View("NewCountryForm", country);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "CanManageHotels")]
        public IActionResult SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
            {
                return View("NewCountryForm", country);
            }

            if (country.Id == 0)
                _context.Countries.Add(country);
            else
            {
                var countryInDb = _context.Countries.Single(c => c.Id == country.Id);
                countryInDb.Name = country.Name;
            }

            _context.SaveChanges();

            return RedirectToAction("New", "Hotels");
        }
    }
}