using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<Customer> Customers { get; set; } = null!;
        public DbSet<Hotel> Hotels { get; set; } = null!;
        public DbSet<Country> Countries { get; set; } = null!;
        public DbSet<Order> Orders { get; set; } = null!;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure entity relationships
            builder.Entity<Hotel>()
                .HasOne(h => h.Country)
                .WithMany()
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<Order>()
                .HasOne(o => o.Hotel)
                .WithMany()
                .HasForeignKey(o => o.HotelId)
                .OnDelete(DeleteBehavior.Restrict);
                
            builder.Entity<Order>()
                .HasOne(o => o.Customer)
                .WithMany()
                .HasForeignKey(o => o.CustomerId)
                .OnDelete(DeleteBehavior.Restrict);

            // Configure property constraints
            builder.Entity<Country>()
                .Property(c => c.Name)
                .IsRequired()
                .HasMaxLength(255);

            builder.Entity<Customer>()
                .Property(c => c.Name)
                .IsRequired()
                .HasMaxLength(255);

            builder.Entity<Hotel>()
                .Property(h => h.Name)
                .IsRequired()
                .HasMaxLength(255);

            builder.Entity<Hotel>()
                .Property(h => h.City)
                .IsRequired()
                .HasMaxLength(50);

            builder.Entity<Hotel>()
                .Property(h => h.Price)
                .HasPrecision(18, 2);  // Using decimal instead of double for currency

            builder.Entity<Order>()
                .Property(o => o.FullPrice)
                .HasPrecision(18, 2);  // Using decimal instead of double for currency
        }
    }
}