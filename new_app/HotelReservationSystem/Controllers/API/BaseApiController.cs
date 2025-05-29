using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers.API
{
    [ApiController]
    [Route("api/[controller]")]
    public abstract class BaseApiController : ControllerBase
    {
        protected readonly ILogger<BaseApiController> _logger;
        
        protected BaseApiController(ILogger<BaseApiController> logger)
        {
            _logger = logger;
        }
        
        protected ActionResult HandleException(Exception ex)
        {
            _logger.LogError(ex, "An error occurred");
            return StatusCode(500, "An unexpected error occurred");
        }
    }
}