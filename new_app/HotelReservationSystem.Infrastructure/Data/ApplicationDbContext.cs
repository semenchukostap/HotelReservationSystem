using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Infrastructure.Data
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
            
            // Configure entity relationships and constraints here
            builder.Entity<Hotel>()
                .HasOne(h => h.Country)
                .WithMany(c => c.Hotels)
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Restrict);
            
            builder.Entity<Order>()
                .HasOne(o => o.Hotel)
                .WithMany()
                .HasForeignKey(o => o.HotelId)
                .OnDelete(DeleteBehavior.Restrict);
            
            builder.Entity<Order>()
                .HasOne(o => o.User)
                .WithMany(u => u.Orders)
                .HasForeignKey(o => o.UserId)
                .OnDelete(DeleteBehavior.Restrict);
        }
    }
}