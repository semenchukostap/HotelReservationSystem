using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Controllers.API;

[Route("api/[controller]")]
[ApiController]
[Authorize(Roles = RoleName.Admin)]
[Produces("application/json")]
public class CustomersController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<CustomersController> _logger;

    public CustomersController(ApplicationDbContext context, ILogger<CustomersController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Gets all customers
    /// </summary>
    /// <returns>A collection of customers</returns>
    /// <response code="200">Returns the list of customers</response>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<Customer>>> GetCustomers()
    {
        _logger.LogInformation("Getting all customers");
        return await _context.Customers.ToListAsync();
    }

    /// <summary>
    /// Gets a specific customer by id
    /// </summary>
    /// <param name="id">The customer ID</param>
    /// <returns>The requested customer</returns>
    /// <response code="200">Returns the customer</response>
    /// <response code="404">If customer is not found</response>
    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<Customer>> GetCustomer(int id)
    {
        _logger.LogInformation("Getting customer with ID {CustomerId}", id);
        
        var customer = await _context.Customers.FindAsync(id);

        if (customer is null)
        {
            _logger.LogWarning("Customer with ID {CustomerId} not found", id);
            return NotFound();
        }

        return customer;
    }

    /// <summary>
    /// Creates a new customer
    /// </summary>
    /// <param name="customer">The customer to create</param>
    /// <returns>The created customer</returns>
    /// <response code="201">Returns the newly created customer</response>
    /// <response code="400">If the customer data is invalid</response>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<Customer>> CreateCustomer(Customer customer)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Invalid customer model state");
            return BadRequest(ModelState);
        }

        _context.Customers.Add(customer);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created customer with ID {CustomerId}", customer.Id);
        return CreatedAtAction(nameof(GetCustomer), new { id = customer.Id }, customer);
    }

    /// <summary>
    /// Updates a specific customer
    /// </summary>
    /// <param name="id">The customer ID</param>
    /// <param name="customer">The updated customer data</param>
    /// <returns>No content</returns>
    /// <response code="204">If the customer was successfully updated</response>
    /// <response code="400">If the request data is invalid</response>
    /// <response code="404">If the customer is not found</response>
    [HttpPut("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateCustomer(int id, Customer customer)
    {
        if (id != customer.Id)
        {
            _logger.LogWarning("Customer ID mismatch: path ID {PathId} vs body ID {BodyId}", id, customer.Id);
            return BadRequest("ID in the URL must match the ID in the request body");
        }

        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Invalid customer model state");
            return BadRequest(ModelState);
        }

        _context.Entry(customer).State = EntityState.Modified;

        try
        {
            await _context.SaveChangesAsync();
            _logger.LogInformation("Updated customer with ID {CustomerId}", id);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            if (!await CustomerExistsAsync(id))
            {
                _logger.LogWarning("Customer with ID {CustomerId} not found during update", id);
                return NotFound();
            }
            
            _logger.LogError(ex, "Concurrency error while updating customer {CustomerId}", id);
            throw;
        }

        return NoContent();
    }

    /// <summary>
    /// Deletes a specific customer
    /// </summary>
    /// <param name="id">The customer ID to delete</param>
    /// <returns>No content</returns>
    /// <response code="204">If the customer was successfully deleted</response>
    /// <response code="404">If the customer is not found</response>
    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteCustomer(int id)
    {
        var customer = await _context.Customers.FindAsync(id);
        if (customer is null)
        {
            _logger.LogWarning("Customer with ID {CustomerId} not found for deletion", id);
            return NotFound();
        }

        _context.Customers.Remove(customer);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Deleted customer with ID {CustomerId}", id);
        return NoContent();
    }

    private async Task<bool> CustomerExistsAsync(int id)
    {
        return await _context.Customers.AnyAsync(e => e.Id == id);
    }
}
