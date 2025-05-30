using Microsoft.AspNetCore.Identity.UI.Services;

namespace HotelReservationSystem.Services
{
    public class EmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // Implementation would go here
            return Task.CompletedTask;
        }
    }
}