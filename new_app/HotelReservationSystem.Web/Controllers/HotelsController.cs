using HotelReservationSystem.Core.Constants;
using HotelReservationSystem.Core.Interfaces;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace HotelReservationSystem.Web.Controllers
{
    public class HotelsController : Controller
    {
        private readonly IRepository<Hotel> _hotelRepository;
        private readonly IRepository<Country> _countryRepository;
        
        public HotelsController(IRepository<Hotel> hotelRepository, IRepository<Country> countryRepository)
        {
            _hotelRepository = hotelRepository;
            _countryRepository = countryRepository;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            if (User.IsInRole(RoleNames.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }

        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<IActionResult> New()
        {
            var countries = await _countryRepository.GetAllAsync();

            var viewModel = new HotelViewModel
            {
                Hotel = new Hotel(),
                Countries = countries
            };

            return View("Form", viewModel);
        }

        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<IActionResult> Edit(int id)
        {
            var hotel = await _hotelRepository.GetByIdAsync(id);

            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _countryRepository.GetAllAsync()
            };

            return View("Form", viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<IActionResult> Save(Hotel hotel)
        {
            if (!ModelState.IsValid)
            {
                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _countryRepository.GetAllAsync()
                };

                return View("Form", viewModel);
            }

            if (hotel.Id == 0)
                await _hotelRepository.AddAsync(hotel);
            else
            {
                var hotelInDb = await _hotelRepository.GetByIdAsync(hotel.Id);
                if (hotelInDb != null)
                {
                    hotelInDb.Name = hotel.Name;
                    hotelInDb.City = hotel.City;
                    hotelInDb.CountryId = hotel.CountryId;
                    hotelInDb.IsAllInclusive = hotel.IsAllInclusive;
                    hotelInDb.PricePerNight = hotel.PricePerNight;
                    hotelInDb.Stars = hotel.Stars;
                    
                    await _hotelRepository.UpdateAsync(hotelInDb);
                }
            }

            return RedirectToAction("Index", "Hotels");
        }

        public IActionResult NewCountry()
        {
            var country = new Country();

            return View("NewCountryForm", country);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleNames.CanManageHotels)]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
            {
                return View("NewCountryForm", country);
            }

            if (country.Id == 0)
                await _countryRepository.AddAsync(country);
            else
            {
                var countryInDb = await _countryRepository.GetByIdAsync(country.Id);
                if (countryInDb != null)
                {
                    countryInDb.Name = country.Name;
                    await _countryRepository.UpdateAsync(countryInDb);
                }
            }

            return RedirectToAction("New", "Hotels");
        }
    }
}