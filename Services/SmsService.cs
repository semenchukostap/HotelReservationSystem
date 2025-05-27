namespace HotelReservationSystem.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }

    public class SmsService : ISmsSender
    {
        private readonly ILogger<SmsService> _logger;

        public SmsService(ILogger<SmsService> logger)
        {
            _logger = logger;
        }

        public Task SendSmsAsync(string number, string message)
        {
            _logger.LogInformation($"SMS: {number}, Message: {message}");
            // Implementation for SMS sending would go here
            return Task.CompletedTask;
        }
    }
}