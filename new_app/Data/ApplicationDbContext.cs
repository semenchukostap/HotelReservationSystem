using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
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
        /// Gets or sets the customers in the system.
        /// </summary>
        public DbSet<Customer> Customers => Set<Customer>();

        /// <summary>
        /// Gets or sets the hotels in the system.
        /// </summary>
        public DbSet<Hotel> Hotels => Set<Hotel>();

        /// <summary>
        /// Gets or sets the countries in the system.
        /// </summary>
        public DbSet<Country> Countries => Set<Country>();

        /// <summary>
        /// Gets or sets the orders in the system.
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
        /// <exception cref="ArgumentNullException">Thrown when builder is null.</exception>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            if (builder == null)
                throw new ArgumentNullException(nameof(builder));

            base.OnModelCreating(builder);

            // Apply entity configurations through IEntityTypeConfiguration classes
            builder.ApplyConfiguration(new HotelConfiguration());
            builder.ApplyConfiguration(new OrderConfiguration());
            builder.ApplyConfiguration(new CustomerConfiguration());
            builder.ApplyConfiguration(new CountryConfiguration());
            builder.ApplyConfiguration(new ApplicationUserConfiguration());
        }

        /// <summary>
        /// Configures the database to be used.
        /// </summary>
        /// <param name="optionsBuilder">The options builder used to configure the context.</param>
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseLazyLoadingProxies();
            }
            
            base.OnConfiguring(optionsBuilder);
        }
    }

    /// <summary>
    /// Configuration class for the Hotel entity.
    /// </summary>
    public class HotelConfiguration : IEntityTypeConfiguration<Hotel>
    {
        /// <summary>
        /// Configures the entity of type Hotel.
        /// </summary>
        /// <param name="builder">The builder to be used to configure the entity type.</param>
        public void Configure(EntityTypeBuilder<Hotel> builder)
        {
            builder.ToTable("Hotels");
            
            // Primary key
            builder.HasKey(h => h.Id);
            
            // Properties
            builder.Property(h => h.Name)
                .IsRequired()
                .HasMaxLength(255);
                
            builder.Property(h => h.Description)
                .HasMaxLength(2000);
                
            builder.Property(h => h.City)
                .IsRequired()
                .HasMaxLength(50);

            builder.Property(h => h.Stars)
                .IsRequired();

            builder.Property(h => h.PricePerNight)
                .IsRequired()
                .HasPrecision(18, 2);
                
            // Relationships
            builder.HasOne(h => h.Country)
                .WithMany(c => c.Hotels)
                .HasForeignKey(h => h.CountryId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);
                
            // Indexes for performance
            builder.HasIndex(h => h.Name);
            builder.HasIndex(h => new { h.CountryId, h.City });
        }
    }

    /// <summary>
    /// Configuration class for the Order entity.
    /// </summary>
    public class OrderConfiguration : IEntityTypeConfiguration<Order>
    {
        /// <summary>
        /// Configures the entity of type Order.
        /// </summary>
        /// <param name="builder">The builder to be used to configure the entity type.</param>
        public void Configure(EntityTypeBuilder<Order> builder)
        {
            builder.ToTable("Orders");
            
            // Primary key
            builder.HasKey(o => o.Id);
            
            // Properties
            builder.Property(o => o.CheckInDate)
                .IsRequired();
                
            builder.Property(o => o.CheckOutDate)
                .IsRequired();
                
            builder.Property(o => o.TotalPrice)
                .IsRequired()
                .HasPrecision(18, 2);
                
            builder.Property(o => o.CreatedDate)
                .IsRequired()
                .HasDefaultValueSql("GETUTCDATE()");
                
            // Add a check constraint to ensure checkout date is after checkin date
            builder.HasCheckConstraint("CK_Orders_CheckOutDate_After_CheckInDate", 
                "CheckOutDate > CheckInDate");
                
            // Relationships
            builder.HasOne(o => o.Customer)
                .WithMany(c => c.Orders)
                .HasForeignKey(o => o.CustomerId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            builder.HasOne(o => o.Hotel)
                .WithMany(h => h.Orders)
                .HasForeignKey(o => o.HotelId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);
                
            // Indexes
            builder.HasIndex(o => o.CreatedDate);
        }
    }

    /// <summary>
    /// Configuration class for the Customer entity.
    /// </summary>
    public class CustomerConfiguration : IEntityTypeConfiguration<Customer>
    {
        /// <summary>
        /// Configures the entity of type Customer.
        /// </summary>
        /// <param name="builder">The builder to be used to configure the entity type.</param>
        public void Configure(EntityTypeBuilder<Customer> builder)
        {
            builder.ToTable("Customers");
            
            // Primary key
            builder.HasKey(c => c.Id);
            
            // Properties
            builder.Property(c => c.Name)
                .IsRequired()
                .HasMaxLength(255);
                
            builder.Property(c => c.Email)
                .IsRequired()
                .HasMaxLength(255);
                
            builder.Property(c => c.Phone)
                .HasMaxLength(20);
                
            // Indexes
            builder.HasIndex(c => c.Email)
                .IsUnique();
        }
    }
    
    /// <summary>
    /// Configuration class for the Country entity.
    /// </summary>
    public class CountryConfiguration : IEntityTypeConfiguration<Country>
    {
        /// <summary>
        /// Configures the entity of type Country.
        /// </summary>
        /// <param name="builder">The builder to be used to configure the entity type.</param>
        public void Configure(EntityTypeBuilder<Country> builder)
        {
            builder.ToTable("Countries");
            
            // Primary key
            builder.HasKey(c => c.Id);
            
            // Properties
            builder.Property(c => c.Name)
                .IsRequired()
                .HasMaxLength(100);
                
            builder.Property(c => c.Code)
                .IsRequired()
                .HasMaxLength(3);
                
            // Indexes
            builder.HasIndex(c => c.Name);
            builder.HasIndex(c => c.Code)
                .IsUnique();
        }
    }
    
    /// <summary>
    /// Configuration class for the ApplicationUser entity.
    /// </summary>
    public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
    {
        /// <summary>
        /// Configures the entity of type ApplicationUser.
        /// </summary>
        /// <param name="builder">The builder to be used to configure the entity type.</param>
        public void Configure(EntityTypeBuilder<ApplicationUser> builder)
        {
            // Properties
            builder.Property(u => u.Phone)
                .IsRequired()
                .HasMaxLength(20);
            
            builder.Property(u => u.FirstName)
                .HasMaxLength(100);
            
            builder.Property(u => u.LastName)
                .HasMaxLength(100);
        }
    }
}