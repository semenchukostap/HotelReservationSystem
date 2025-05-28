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

            // Apply entity configurations
            builder.ApplyConfiguration(new HotelConfiguration());
            builder.ApplyConfiguration(new OrderConfiguration());
            builder.ApplyConfiguration(new CustomerConfiguration());
            
            ConfigureHotelEntity(builder);
            ConfigureOrderEntity(builder);
            ConfigureApplicationUserEntity(builder);
            ConfigureCustomerEntity(builder);
        }

        /// <summary>
        /// Configures the database to be used.
        /// </summary>
        /// <param name="optionsBuilder">The options builder used to configure the context.</param>
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseLazyLoadingProxies();
            base.OnConfiguring(optionsBuilder);
        }

        /// <summary>
        /// Configures the Hotel entity.
        /// </summary>
        /// <param name="builder">The model builder instance.</param>
        private void ConfigureHotelEntity(ModelBuilder builder)
        {
            builder.Entity<Hotel>(entity =>
            {
                // Primary key
                entity.HasKey(h => h.Id);
                
                // Relationships
                entity.HasOne(h => h.Country)
                    .WithMany(c => c.Hotels)
                    .HasForeignKey(h => h.CountryId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);

                // Properties
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
                
                // Indexes
                entity.HasIndex(h => h.Name);
                entity.HasIndex(h => new { h.CountryId, h.City });
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
                // Primary key
                entity.HasKey(o => o.Id);
                
                // Relationships
                entity.HasOne(o => o.Customer)
                    .WithMany(c => c.Orders)
                    .HasForeignKey(o => o.CustomerId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasOne(o => o.Hotel)
                    .WithMany(h => h.Orders)
                    .HasForeignKey(o => o.HotelId)
                    .IsRequired()
                    .OnDelete(DeleteBehavior.Restrict);
                
                // Properties
                entity.Property(o => o.TotalPrice)
                    .IsRequired()
                    .HasPrecision(18, 2);
                    
                entity.Property(o => o.CreatedDate)
                    .IsRequired()
                    .HasDefaultValueSql("GETUTCDATE()");
                
                // Indexes
                entity.HasIndex(o => o.CreatedDate);
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
                // Properties
                entity.Property(u => u.Phone)
                    .IsRequired()
                    .HasMaxLength(20);
                
                entity.Property(u => u.FirstName)
                    .HasMaxLength(100);
                
                entity.Property(u => u.LastName)
                    .HasMaxLength(100);
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
                // Primary key
                entity.HasKey(c => c.Id);
                
                // Properties
                entity.Property(c => c.Name)
                    .IsRequired()
                    .HasMaxLength(255);
                
                entity.Property(c => c.Email)
                    .IsRequired()
                    .HasMaxLength(255);
                
                entity.Property(c => c.Phone)
                    .HasMaxLength(20);
                
                // Indexes
                entity.HasIndex(c => c.Email)
                    .IsUnique();
            });
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
            
            builder.HasKey(h => h.Id);
            
            builder.Property(h => h.Name)
                .IsRequired()
                .HasMaxLength(255);
                
            builder.Property(h => h.Description)
                .HasMaxLength(2000);
                
            builder.HasOne(h => h.Country)
                .WithMany(c => c.Hotels)
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Restrict);
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
            
            builder.HasKey(o => o.Id);
            
            builder.Property(o => o.CheckInDate)
                .IsRequired();
                
            builder.Property(o => o.CheckOutDate)
                .IsRequired();
                
            // Add a check constraint to ensure checkout date is after checkin date
            builder.HasCheckConstraint("CK_Orders_CheckOutDate_After_CheckInDate", 
                "CheckOutDate > CheckInDate");
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
            
            builder.HasKey(c => c.Id);
            
            builder.Property(c => c.Name)
                .IsRequired()
                .HasMaxLength(255);
                
            builder.Property(c => c.Email)
                .IsRequired()
                .HasMaxLength(255);
                
            builder.HasIndex(c => c.Email)
                .IsUnique();
        }
    }
}
