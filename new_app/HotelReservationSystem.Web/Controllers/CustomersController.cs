using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Web.Controllers
{
    public class CustomersController : Controller
    {
        private readonly ICustomerService _customerService;

        public CustomersController(ICustomerService customerService)
        {
            _customerService = customerService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult New()
        {
            var customer = new Customer();
            return View("Form", customer);
        }

        public async Task<IActionResult> Edit(int id)
        {
            var customerDto = await _customerService.GetCustomerByIdAsync(id);
            if (customerDto == null)
                return NotFound();

            var customer = new Customer
            {
                Id = customerDto.Id,
                Name = customerDto.Name,
                Birthdate = customerDto.Birthdate
            };

            return View("Form", customer);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(Customer customer)
        {
            if (!ModelState.IsValid)
                return View("Form", customer);

            var customerDto = new CustomerDto
            {
                Id = customer.Id,
                Name = customer.Name,
                Birthdate = customer.Birthdate
            };

            if (customer.Id == 0)
                await _customerService.CreateCustomerAsync(customerDto);
            else
                await _customerService.UpdateCustomerAsync(customer.Id, customerDto);

            return RedirectToAction("Index");
        }
    }
}