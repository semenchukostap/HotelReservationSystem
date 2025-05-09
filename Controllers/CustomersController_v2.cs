using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HotelReservationSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CustomersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CustomersController(ApplicationDbContext context)
        {
            _context = context;
        }

        protected override void Dispose(bool disposing)
        {
            _context.Dispose();
        }

        [HttpGet]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult Index()
        {
            return Ok(); // Changed from View() to Ok() for API response
        }

        [HttpGet("new")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult New()
        {
            var customer = new Customer();
            return Ok(customer); // Changed from View("Form", customer) to Ok(customer) for API response
        }

        [HttpGet("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult Edit(int id)
        {
            var customer = _context.Customers.SingleOrDefault(c => c.Id == id);

            if (customer == null)
                return NotFound();

            return Ok(customer); // Changed from View("Form", customer) to Ok(customer) for API response
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ValidateAntiForgeryToken]
        public IActionResult Save(Customer customer)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (customer.Id == 0)
                _context.Customers.Add(customer);
            else
            {
                var customerInDb = _context.Customers.Single(c => c.Id == customer.Id);
                customerInDb.Name = customer.Name;
                customerInDb.Birthdate = customer.Birthdate;
            }

            _context.SaveChanges();

            return RedirectToAction("Index", "Customers"); // This can be updated to an appropriate API response if needed
        }
    }
}
