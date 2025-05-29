# Service Collection Extensions

This directory contains extension methods for the `IServiceCollection` to better organize service registrations and configuration in the application.

## Why Use Extension Methods?

Extension methods provide a way to keep the `Program.cs` file clean and maintainable by extracting service registration logic into dedicated methods. This makes the code more:

- **Maintainable**: Each service category has its own configuration method
- **Testable**: Isolated configuration can be tested independently
- **Readable**: `Program.cs` becomes more concise and easier to understand
- **Modifiable**: Changes to service configuration can be made in isolation

## Available Extensions

The `ServiceCollectionExtensions` class includes the following extension methods:

- `AddDatabaseServices`: Configures database context with SQL Server and performance settings
- `AddIdentityServices`: Sets up ASP.NET Core Identity with customized options
- `AddMvcServices`: Configures MVC with anti-forgery, JSON options, and other MVC features
- `AddAutoMapperServices`: Registers AutoMapper and discovers mapping profiles
- `AddApiBehaviorServices`: Configures API behavior options
- `AddApplicationServices`: Registers application-specific services like the email sender

## How to Use

In your `Program.cs` file, use these extension methods to configure services:

```csharp
// Add services to the container using extension methods for clean organization
builder.Services.AddDatabaseServices(builder.Configuration);
builder.Services.AddIdentityServices();
builder.Services.AddMvcServices();
builder.Services.AddAutoMapperServices();
builder.Services.AddApiBehaviorServices();
builder.Services.AddApplicationServices();
```

## Adding New Extensions

To add a new extension method:

1. Decide which logical group the service belongs to
2. Add a new method in `ServiceCollectionExtensions.cs` or create a new extension class
3. Ensure the method returns `IServiceCollection` to allow method chaining
4. Use your new extension method in `Program.cs`

## Best Practices

- Keep related services together in the same extension method
- Add XML comments to document each extension method
- Return `IServiceCollection` to enable method chaining
- Use meaningful method names that describe what services are being added