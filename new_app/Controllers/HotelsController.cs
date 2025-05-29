using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Controllers
{
    [Authorize]
    public class HotelsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;
        
        public HotelsController(ApplicationDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

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
            var viewModel = new HotelFormViewModel
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

            var viewModel = new HotelFormViewModel
            {
                Hotel = hotel,
                Countries = await _context.Countries.ToListAsync()
            };

            return View("Form", viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Save(HotelFormViewModel viewModel)
        {
            if (!ModelState.IsValid)
            {
                viewModel.Countries = await _context.Countries.ToListAsync();
                return View("Form", viewModel);
            }

            if (viewModel.Hotel.Id == 0)
            {
                await _context.Hotels.AddAsync(viewModel.Hotel);
            }
            else
            {
                var hotelInDb = await _context.Hotels.FindAsync(viewModel.Hotel.Id);
                if (hotelInDb == null)
                    return NotFound();

                _mapper.Map(viewModel.Hotel, hotelInDb);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult NewCountry()
        {
            return View("CountryForm", new Country());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> SaveCountry(Country country)
        {
            if (!ModelState.IsValid)
                return View("CountryForm", country);

            if (country.Id == 0)
            {
                await _context.Countries.AddAsync(country);
            }
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
    }
}