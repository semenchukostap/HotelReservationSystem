namespace HotelReservationSystem.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }

    public class EmailSender : IEmailSender
    {
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(ILogger<EmailSender> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string email, string subject, string message)
        {
            // In a real app, you would implement email sending
            _logger.LogInformation($"Email: {email}, Subject: {subject}, Message: {message}");
            return Task.CompletedTask;
        }
    }
}