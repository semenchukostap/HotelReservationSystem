using Microsoft.AspNetCore.Identity.UI.Services;

namespace HotelReservationSystem.Services
{
    public interface IEmailSender : IEmailSender
    {
    }

    public class EmailService : IEmailSender
    {
        private readonly ILogger<EmailService> _logger;

        public EmailService(ILogger<EmailService> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            _logger.LogInformation($"Email: {email}, Subject: {subject}");
            // Implementation for email sending would go here
            return Task.CompletedTask;
        }
    }
}