using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers
{
    public class CustomersController : Controller
    {
        private readonly ICustomerService _customerService;
        private readonly IMapper _mapper;

        public CustomersController(ICustomerService customerService, IMapper mapper)
        {
            _customerService = customerService;
            _mapper = mapper;
        }

        public async Task<IActionResult> Index()
        {
            var customers = await _customerService.GetAllCustomersAsync();
            return View(customers);
        }

        public async Task<IActionResult> Form(int? id)
        {
            if (!id.HasValue)
                return View(new CustomerViewModel());

            var customer = await _customerService.GetCustomerByIdAsync(id.Value);
            if (customer == null)
                return NotFound();

            var viewModel = _mapper.Map<CustomerViewModel>(customer);
            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(CustomerViewModel viewModel)
        {
            if (!ModelState.IsValid)
                return View("Form", viewModel);

            var customer = _mapper.Map<Customer>(viewModel);

            if (viewModel.Id == 0 || viewModel.Id == null)
                await _customerService.CreateCustomerAsync(customer);
            else
                await _customerService.UpdateCustomerAsync(customer);

            return RedirectToAction("Index");
        }
    }
}