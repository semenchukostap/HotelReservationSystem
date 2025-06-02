# Hotel Reservation System - .NET 8 Migration

This project is a migration of the Hotel Reservation System from .NET Framework 4.5.2 and ASP.NET MVC 5 to .NET 8 and ASP.NET Core MVC.

## Migration Approach

We're following Microsoft's recommended approach for migrating ASP.NET MVC to ASP.NET Core:

1. **Side-by-side migration**: Creating a new ASP.NET Core project alongside the existing application
2. **Incremental feature migration**: Moving features one by one from the old to the new application
3. **Shared database approach**: Both applications can access the same database during migration
4. **Component-by-component migration**: Starting with models, then controllers, views, and services

## Project Structure

- `/HotelReservationSystem` - Main ASP.NET Core MVC application
- `/HotelReservationSystem/Data` - Database context and configuration
- `/HotelReservationSystem/Models` - Domain models
- `/HotelReservationSystem/DTOs` - Data transfer objects for APIs
- `/HotelReservationSystem/Controllers` - MVC controllers
- `/HotelReservationSystem/Controllers/API` - API controllers
- `/HotelReservationSystem/Views` - Razor views
- `/HotelReservationSystem/Areas` - Feature areas (including Identity)

## Key Technology Updates

- **Authentication**: Migrated from ASP.NET Identity to ASP.NET Core Identity
- **Data Access**: Migrated from Entity Framework 6 to Entity Framework Core 8
- **Dependency Injection**: Using built-in ASP.NET Core DI container instead of OWIN
- **Configuration**: Using the new configuration system with appsettings.json
- **Tag Helpers**: Using ASP.NET Core Tag Helpers instead of HTML Helpers
- **Middleware**: Using ASP.NET Core middleware pipeline instead of OWIN middleware
- **Client-side Libraries**: Using LibMan or npm instead of NuGet for client libraries

## How to Run

1. Make sure you have .NET 8 SDK installed
2. Update the connection string in `appsettings.json` if needed
3. Apply database migrations: `dotnet ef database update`
4. Run the application: `dotnet run`

## Migration Status

### Completed Items
- Basic project structure migration from ASP.NET MVC to ASP.NET Core
- Database context migration to Entity Framework Core 8
- Core domain models migration
- Authentication framework migration to ASP.NET Core Identity
- Identity UI integration, including `_LoginPartial.cshtml` view component
- Configuration system migration to use appsettings.json
- Basic routing setup with endpoint routing

### In Progress
- Controller migration
- View migration (using new Tag Helpers)
- JavaScript and CSS asset management
- API endpoints
- Service layer implementation

### Pending Items
- Complete view migration
- Integration testing
- User role management
- Reservation system core functionality
- Payment processing integration
- Report generation
- Email notification system

See [MIGRATION-STATUS.md](MIGRATION-STATUS.md) for detailed migration progress.