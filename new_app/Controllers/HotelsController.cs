using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers
{
    [Route("hotels")]
    public class HotelsController : Controller
    {
        private readonly IHotelService _hotelService;
        private readonly IMapper _mapper;
        private readonly ILogger<HotelsController> _logger;

        public HotelsController(
            IHotelService hotelService, 
            IMapper mapper,
            ILogger<HotelsController> logger)
        {
            _hotelService = hotelService ?? throw new ArgumentNullException(nameof(hotelService));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        [HttpGet]
        [Route("")]
        public async Task<IActionResult> List()
        {
            try
            {
                _logger.LogInformation("Retrieving all hotels");
                var hotels = await _hotelService.GetAllHotelsAsync();
                return View(hotels);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while retrieving hotels");
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpGet]
        [Route("form/{id:int?}")]
        [Authorize(Roles = "Admin," + RoleName.CanManageHotels)]
        public async Task<IActionResult> Form(int? id)
        {
            try
            {
                _logger.LogInformation("Preparing hotel form for id: {HotelId}", id);
                
                var countries = await _hotelService.GetAllCountriesAsync();
                var countrySelectItems = countries
                    .Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name })
                    .OrderBy(c => c.Text)
                    .ToList();
                
                var viewModel = new HotelViewModel
                {
                    Countries = countrySelectItems
                };

                if (!id.HasValue)
                    return View(viewModel);

                var hotel = await _hotelService.GetHotelByIdAsync(id.Value);
                if (hotel == null)
                {
                    _logger.LogWarning("Hotel with id {HotelId} not found", id.Value);
                    return NotFound();
                }

                viewModel = _mapper.Map<HotelViewModel>(hotel);
                viewModel.Countries = countrySelectItems;

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error preparing hotel form for id: {HotelId}", id);
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpPost]
        [Route("save")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin," + RoleName.CanManageHotels)]
        public async Task<IActionResult> Save(HotelViewModel viewModel)
        {
            try
            {
                _logger.LogInformation("Saving hotel with id: {HotelId}", viewModel.Id);
                
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Invalid model state when saving hotel");
                    var countries = await _hotelService.GetAllCountriesAsync();
                    viewModel.Countries = countries
                        .Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name })
                        .OrderBy(c => c.Text)
                        .ToList();

                    return View("Form", viewModel);
                }

                var hotel = _mapper.Map<Hotel>(viewModel);

                if (viewModel.Id == 0)
                {
                    _logger.LogInformation("Creating new hotel");
                    await _hotelService.CreateHotelAsync(hotel);
                    TempData["SuccessMessage"] = "Hotel created successfully";
                }
                else
                {
                    _logger.LogInformation("Updating existing hotel with id: {HotelId}", viewModel.Id);
                    await _hotelService.UpdateHotelAsync(hotel);
                    TempData["SuccessMessage"] = "Hotel updated successfully";
                }

                return RedirectToAction(nameof(List));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving hotel with id: {HotelId}", viewModel.Id);
                ModelState.AddModelError("", "An error occurred while saving the hotel");
                
                var countries = await _hotelService.GetAllCountriesAsync();
                viewModel.Countries = countries
                    .Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name })
                    .OrderBy(c => c.Text)
                    .ToList();
                    
                return View("Form", viewModel);
            }
        }

        [HttpGet]
        [Route("readonly")]
        public async Task<IActionResult> ReadOnlyList()
        {
            try
            {
                _logger.LogInformation("Retrieving readonly list of hotels");
                var hotels = await _hotelService.GetAllHotelsAsync();
                return View(hotels);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving readonly list of hotels");
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpGet]
        [Route("country/new")]
        [Authorize(Roles = "Admin," + RoleName.CanManageHotels)]
        public IActionResult NewCountryForm()
        {
            return View();
        }
        
        [HttpGet]
        [Route("{id:int}")]
        public async Task<IActionResult> Details(int id)
        {
            try
            {
                _logger.LogInformation("Retrieving hotel details for id: {HotelId}", id);
                var hotel = await _hotelService.GetHotelByIdAsync(id);
                
                if (hotel == null)
                {
                    _logger.LogWarning("Hotel with id {HotelId} not found", id);
                    return NotFound();
                }
                
                return View(hotel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving hotel details for id: {HotelId}", id);
                return StatusCode(500, "An error occurred while processing your request");
            }
        }
    }
}
