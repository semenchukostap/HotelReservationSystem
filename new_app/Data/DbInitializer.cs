using System.Linq;
using System.Threading.Tasks;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data;

public static class DbInitializer
{
    public static async Task Initialize(ApplicationDbContext context)
    {
        await context.Database.EnsureCreatedAsync();

        // Check if the database has been seeded
        if (context.Countries.Any())
        {
            return; // DB has been seeded
        }

        // Seed Countries
        var countries = new[]
        {
            new Country { Name = "Bulgaria" },
            new Country { Name = "Greece" },
            new Country { Name = "Turkey" },
            new Country { Name = "Spain" },
            new Country { Name = "Italy" },
            new Country { Name = "Egypt" },
            new Country { Name = "Poland" },
            new Country { Name = "Germany" },
            new Country { Name = "Malta" },
            new Country { Name = "France" },
            new Country { Name = "Portugal" }, // Fixed typo from original migration
            new Country { Name = "England" }
        };

        await context.Countries.AddRangeAsync(countries);
        await context.SaveChangesAsync();

        // Add more seed data as needed
    }
}