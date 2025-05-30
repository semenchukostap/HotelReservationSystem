using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using HotelReservationSystem.Models;
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
            
            // Define any additional model configurations here
            // This replaces the Entity Framework Fluent API configurations
            
            // Configure relationships between entities
            builder.Entity<Order>(entity =>
            {
                entity.HasOne(o => o.Customer)
                    .WithMany()
                    .HasForeignKey(o => o.CustomerId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);
                
                entity.HasOne(o => o.Hotel)
                    .WithMany()
                    .HasForeignKey(o => o.HotelId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);

                // Configure any additional properties
                entity.Property(o => o.DateCreated).IsRequired();
                entity.Property(o => o.CheckIn).IsRequired();
                entity.Property(o => o.CheckOut).IsRequired();
                entity.Property(o => o.FullPrice).HasColumnType("decimal(18, 2)");
            });
            
            builder.Entity<Hotel>(entity =>
            {
                entity.HasOne(h => h.Country)
                    .WithMany()
                    .HasForeignKey(h => h.CountryId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);
                
                entity.Property(h => h.Name).IsRequired().HasMaxLength(255);
                entity.Property(h => h.City).IsRequired().HasMaxLength(50);
                entity.Property(h => h.Stars).IsRequired();
                entity.Property(h => h.PricePerNight).IsRequired();
                entity.Property(h => h.IsAllInclusive).IsRequired();
            });

            builder.Entity<Country>(entity =>
            {
                entity.Property(c => c.Name).IsRequired().HasMaxLength(50);
            });

            builder.Entity<Customer>(entity =>
            {
                entity.Property(c => c.Name).IsRequired().HasMaxLength(255);
            });

            builder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(u => u.Phone).IsRequired().HasMaxLength(20);
            });
        }
    }
}