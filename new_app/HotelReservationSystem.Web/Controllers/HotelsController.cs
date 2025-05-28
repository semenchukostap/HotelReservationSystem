using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Web.Controllers
{
    public class HotelsController : Controller
    {
        private readonly IHotelService _hotelService;
        private readonly ICountryService _countryService;

        public HotelsController(IHotelService hotelService, ICountryService countryService)
        {
            _hotelService = hotelService;
            _countryService = countryService;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            if (User.IsInRole(RoleConstants.CanManageHotels))
                return View("List");

            return View("ReadOnlyList");
        }

        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> New()
        {
            var countries = await _countryService.GetAllCountriesEntitiesAsync();

            var viewModel = new HotelViewModel
            {
                Hotel = new Hotel(),
                Countries = countries
            };

            return View("Form", viewModel);
        }

        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> Edit(int id)
        {
            var hotel = await _hotelService.GetHotelEntityByIdAsync(id);

            if (hotel == null)
                return NotFound();

            var viewModel = new HotelViewModel
            {
                Hotel = hotel,
                Countries = await _countryService.GetAllCountriesEntitiesAsync()
            };

            return View("Form", viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> Save(Hotel hotel)
        {
            if (!ModelState.IsValid)
            {
                var viewModel = new HotelViewModel
                {
                    Hotel = hotel,
                    Countries = await _countryService.GetAllCountriesEntitiesAsync()
                };

                return View("Form", viewModel);
            }

            var hotelDto = new HotelDto
            {
                Id = hotel.Id,
                Name = hotel.Name,
                City = hotel.City,
                CountryId = hotel.CountryId,
                IsAllInclusive = hotel.IsAllInclusive,
                PricePerNight = hotel.PricePerNight,
                Stars = hotel.Stars
            };

            if (hotel.Id == 0)
                await _hotelService.CreateHotelAsync(hotelDto);
            else
                await _hotelService.UpdateHotelAsync(hotel.Id, hotelDto);

            return RedirectToAction("Index", "Hotels");
        }

        public IActionResult NewCountry()
        {
            return View("NewCountryForm", new Country());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "CanManageHotels")]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
            {
                return View("NewCountryForm", country);
            }

            var countryDto = new CountryDto
            {
                Id = country.Id,
                Name = country.Name
            };

            await _countryService.CreateCountryAsync(countryDto);

            return RedirectToAction("New", "Hotels");
        }
    }
}