using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<Customer> Customers => Set<Customer>();
        public DbSet<Hotel> Hotels => Set<Hotel>();
        public DbSet<Country> Countries => Set<Country>();
        public DbSet<Order> Orders => Set<Order>();

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
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            builder.Entity<Order>()
                .HasOne(o => o.Customer)
                .WithMany()
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            builder.Entity<Order>()
                .HasOne(o => o.Hotel)
                .WithMany()
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            // Configure property constraints
            builder.Entity<ApplicationUser>()
                .Property(u => u.Phone)
                .IsRequired()
                .HasMaxLength(20);

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
                .Property(h => h.Stars)
                .IsRequired();

            builder.Entity<Hotel>()
                .Property(h => h.PricePerNight)
                .IsRequired();
        }
    }
}