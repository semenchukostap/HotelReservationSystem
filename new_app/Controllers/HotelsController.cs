using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.Controllers
{
    public class HotelsController : Controller
    {
        private readonly IHotelService _hotelService;
        private readonly IMapper _mapper;

        public HotelsController(IHotelService hotelService, IMapper mapper)
        {
            _hotelService = hotelService;
            _mapper = mapper;
        }

        public async Task<IActionResult> List()
        {
            var hotels = await _hotelService.GetAllHotelsAsync();
            return View(hotels);
        }

        [Authorize(Roles = "Admin," + RoleName.CanManageHotels)]
        public async Task<IActionResult> Form(int? id)
        {
            var viewModel = new HotelViewModel
            {
                Countries = (await _hotelService.GetAllCountriesAsync())
                    .Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name })
                    .OrderBy(c => c.Text)
            };

            if (!id.HasValue)
                return View(viewModel);

            var hotel = await _hotelService.GetHotelByIdAsync(id.Value);
            if (hotel == null)
                return NotFound();

            viewModel = _mapper.Map<HotelViewModel>(hotel);
            viewModel.Countries = (await _hotelService.GetAllCountriesAsync())
                .Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name })
                .OrderBy(c => c.Text);

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin," + RoleName.CanManageHotels)]
        public async Task<IActionResult> Save(HotelViewModel viewModel)
        {
            if (!ModelState.IsValid)
            {
                viewModel.Countries = (await _hotelService.GetAllCountriesAsync())
                    .Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name })
                    .OrderBy(c => c.Text);

                return View("Form", viewModel);
            }

            var hotel = _mapper.Map<Hotel>(viewModel);

            if (viewModel.Id == 0)
                await _hotelService.CreateHotelAsync(hotel);
            else
                await _hotelService.UpdateHotelAsync(hotel);

            return RedirectToAction("List");
        }

        public async Task<IActionResult> ReadOnlyList()
        {
            var hotels = await _hotelService.GetAllHotelsAsync();
            return View(hotels);
        }

        [Authorize(Roles = "Admin," + RoleName.CanManageHotels)]
        public IActionResult NewCountryForm()
        {
            return View();
        }
    }
}