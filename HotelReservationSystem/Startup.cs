using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using AutoMapper;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(HotelReservationSystem.Startup))]
namespace HotelReservationSystem
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
            ConfigureAutoMapper();
            ConfigureWebApi(app);
            RegisterGlobalConfigurations();
        }

        private void ConfigureAutoMapper()
        {
            var config = new MapperConfiguration(cfg =>
            {
                // Add your AutoMapper profiles or configurations here
            });

            IMapper mapper = config.CreateMapper();
            // Optionally, you can store the IMapper instance in a DI container
        }

        private void ConfigureWebApi(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            // Optionally, add other Web API configurations here

            app.UseWebApi(config);
        }

        private void RegisterGlobalConfigurations()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
    }
}