using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<Customer> Customers { get; set; }
        public DbSet<Hotel> Hotels { get; set; }
        public DbSet<Country> Countries { get; set; }
        public DbSet<Order> Orders { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            
            // Configure entity relationships and constraints
            builder.Entity<Hotel>()
                .HasOne(h => h.Country)
                .WithMany()
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.Entity<Order>()
                .HasOne(o => o.Customer)
                .WithMany()
                .OnDelete(DeleteBehavior.Restrict);
            
            builder.Entity<Order>()
                .HasOne(o => o.Hotel)
                .WithMany()
                .OnDelete(DeleteBehavior.Restrict);
        }
    }
}