using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class CustomersController : ControllerBase
    {
        private readonly ICustomerService _customerService;
        private readonly IMapper _mapper;

        public CustomersController(ICustomerService customerService, IMapper mapper)
        {
            _customerService = customerService;
            _mapper = mapper;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Customer>>> GetCustomers()
        {
            var customers = await _customerService.GetAllCustomersAsync();
            return Ok(customers);
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Customer>> GetCustomer(int id)
        {
            var customer = await _customerService.GetCustomerByIdAsync(id);

            if (customer == null)
                return NotFound();

            return Ok(customer);
        }

        [HttpPost]
        public async Task<ActionResult<Customer>> CreateCustomer(CustomerViewModel viewModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var customer = _mapper.Map<Customer>(viewModel);
            
            var id = await _customerService.CreateCustomerAsync(customer);

            return CreatedAtAction(nameof(GetCustomer), new { id = customer.Id }, customer);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateCustomer(int id, CustomerViewModel viewModel)
        {
            if (id != viewModel.Id)
                return BadRequest();

            if (!ModelState.IsValid)
                return BadRequest(ModelState);
                
            var customer = await _customerService.GetCustomerByIdAsync(id);
            
            if (customer == null)
                return NotFound();
                
            _mapper.Map(viewModel, customer);
                
            await _customerService.UpdateCustomerAsync(customer);

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteCustomer(int id)
        {
            var customer = await _customerService.GetCustomerByIdAsync(id);
            
            if (customer == null)
                return NotFound();
                
            await _customerService.DeleteCustomerAsync(id);

            return NoContent();
        }
    }
}