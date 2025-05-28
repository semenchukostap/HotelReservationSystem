using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace HotelReservationSystem.Data
{
    /// <summary>
    /// Main database context for the Hotel Reservation System application.
    /// Inherits from IdentityDbContext to support authentication and authorization.
    /// </summary>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        /// <summary>
        /// Gets the customers in the system.
        /// </summary>
        public DbSet<Customer> Customers => Set<Customer>();

        /// <summary>
        /// Gets the hotels in the system.
        /// </summary>
        public DbSet<Hotel> Hotels => Set<Hotel>();

        /// <summary>
        /// Gets the countries in the system.
        /// </summary>
        public DbSet<Country> Countries => Set<Country>();

        /// <summary>
        /// Gets the orders in the system.
        /// </summary>
        public DbSet<Order> Orders => Set<Order>();

        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationDbContext"/> class.
        /// </summary>
        /// <param name="options">The database context options.</param>
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        /// <summary>
        /// Configures the entity models and their relationships when the database is created.
        /// </summary>
        /// <param name="builder">The model builder used to construct the model for this context.</param>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            if (builder == null)
                throw new ArgumentNullException(nameof(builder));
                
            base.OnModelCreating(builder);

            ConfigureHotelEntity(builder);
            ConfigureOrderEntity(builder);
            ConfigureApplicationUserEntity(builder);
            ConfigureCustomerEntity(builder);
        }

        /// <summary>
        /// Configures the Hotel entity.
        /// </summary>
        /// <param name="builder">The model builder instance.</param>
        private void ConfigureHotelEntity(ModelBuilder builder)
        {
            builder.Entity<Hotel>(entity =>
            {
                entity.HasOne(h => h.Country)
                    .WithMany()
                    .HasForeignKey(h => h.CountryId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);

                entity.Property(h => h.Name)
                    .IsRequired()
                    .HasMaxLength(255);

                entity.Property(h => h.City)
                    .IsRequired()
                    .HasMaxLength(50);

                entity.Property(h => h.Stars)
                    .IsRequired();

                entity.Property(h => h.PricePerNight)
                    .IsRequired()
                    .HasPrecision(18, 2);

                entity.HasIndex(h => h.Name);
            });
        }

        /// <summary>
        /// Configures the Order entity.
        /// </summary>
        /// <param name="builder">The model builder instance.</param>
        private void ConfigureOrderEntity(ModelBuilder builder)
        {
            builder.Entity<Order>(entity => 
            {
                entity.HasOne(o => o.Customer)
                    .WithMany()
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(o => o.Hotel)
                    .WithMany()
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);
                    
                entity.Property(o => o.CreatedDate)
                    .IsRequired()
                    .HasDefaultValueSql("GETUTCDATE()");
            });
        }

        /// <summary>
        /// Configures the ApplicationUser entity.
        /// </summary>
        /// <param name="builder">The model builder instance.</param>
        private void ConfigureApplicationUserEntity(ModelBuilder builder)
        {
            builder.Entity<ApplicationUser>(entity => 
            {
                entity.Property(u => u.Phone)
                    .IsRequired()
                    .HasMaxLength(20);
            });
        }

        /// <summary>
        /// Configures the Customer entity.
        /// </summary>
        /// <param name="builder">The model builder instance.</param>
        private void ConfigureCustomerEntity(ModelBuilder builder)
        {
            builder.Entity<Customer>(entity => 
            {
                entity.Property(c => c.Name)
                    .IsRequired()
                    .HasMaxLength(255);
                    
                entity.HasIndex(c => c.Email)
                    .IsUnique();
            });
        }
    }
}