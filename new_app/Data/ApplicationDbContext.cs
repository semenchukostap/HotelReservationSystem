using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Customer> Customers { get; set; }
    public DbSet<Hotel> Hotels { get; set; }
    public DbSet<Country> Countries { get; set; }
    public DbSet<Order> Orders { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure identity tables
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("Users");
            entity.Property(e => e.Phone)
                .IsRequired()
                .HasMaxLength(20);
            
            entity.HasIndex(e => e.Email)
                .IsUnique()
                .HasFilter(null);
            entity.HasIndex(e => e.PhoneNumber)
                .IsUnique()
                .HasFilter(null);
        });

        // Configure Hotel entity
        builder.Entity<Hotel>(entity =>
        {
            entity.ToTable("Hotels", tb => tb.IsTemporal());
            entity.HasKey(e => e.Id);
            
            entity.Property(e => e.Name)
                .IsRequired()
                .HasMaxLength(255)
                .UseCollation("SQL_Latin1_General_CP1_CI_AS");

            entity.HasOne(h => h.Country)
                .WithMany(c => c.Hotels)
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Restrict)
                .IsRequired();

            entity.HasIndex(e => e.Name)
                .HasDatabaseName("IX_Hotels_Name");

            entity.HasIndex(e => new { e.CountryId, e.Name })
                .HasDatabaseName("IX_Hotels_CountryId_Name");
        });

        // Configure Country entity
        builder.Entity<Country>(entity =>
        {
            entity.ToTable("Countries", tb => tb.IsTemporal());
            entity.HasKey(e => e.Id);
            
            entity.Property(e => e.Name)
                .IsRequired()
                .HasMaxLength(100)
                .UseCollation("SQL_Latin1_General_CP1_CI_AS");

            entity.HasIndex(e => e.Name)
                .IsUnique()
                .HasDatabaseName("IX_Countries_Name")
                .HasFilter(null);

            entity.HasMany(c => c.Hotels)
                .WithOne(h => h.Country)
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        // Configure Order entity
        builder.Entity<Order>(entity =>
        {
            entity.ToTable("Orders", tb => tb.IsTemporal());
            entity.HasKey(e => e.Id);

            entity.Property(e => e.CreatedDate)
                .IsRequired()
                .HasDefaultValueSql("GETUTCDATE()")
                .ValueGeneratedOnAdd();

            entity.Property(e => e.TotalAmount)
                .HasPrecision(18, 2);

            entity.HasOne(o => o.Hotel)
                .WithMany(h => h.Orders)
                .HasForeignKey(o => o.HotelId)
                .OnDelete(DeleteBehavior.Restrict)
                .IsRequired();

            entity.HasOne(o => o.Customer)
                .WithMany(c => c.Orders)
                .HasForeignKey(o => o.CustomerId)
                .OnDelete(DeleteBehavior.Restrict)
                .IsRequired();

            entity.HasIndex(e => e.CreatedDate)
                .HasDatabaseName("IX_Orders_CreatedDate");

            entity.HasIndex(e => new { e.CustomerId, e.CreatedDate })
                .HasDatabaseName("IX_Orders_CustomerId_CreatedDate");
        });

        // Configure Customer entity
        builder.Entity<Customer>(entity =>
        {
            entity.ToTable("Customers", tb => tb.IsTemporal());
            entity.HasKey(e => e.Id);

            entity.Property(e => e.FirstName)
                .IsRequired()
                .HasMaxLength(100)
                .UseCollation("SQL_Latin1_General_CP1_CI_AS");

            entity.Property(e => e.LastName)
                .IsRequired()
                .HasMaxLength(100)
                .UseCollation("SQL_Latin1_General_CP1_CI_AS");

            entity.Property(e => e.Email)
                .IsRequired()
                .HasMaxLength(255);

            entity.HasIndex(e => e.Email)
                .IsUnique()
                .HasDatabaseName("IX_Customers_Email")
                .HasFilter(null);

            entity.HasIndex(e => new { e.LastName, e.FirstName })
                .HasDatabaseName("IX_Customers_LastName_FirstName");

            entity.HasMany(c => c.Orders)
                .WithOne(o => o.Customer)
                .HasForeignKey(o => o.CustomerId)
                .OnDelete(DeleteBehavior.Restrict);
        });
    }
}