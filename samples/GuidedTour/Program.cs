using GuidedTour;
using GuidedTour.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.Configure<TourOptions>(builder.Configuration.GetSection("GuidedTour"));
builder.Services.AddScoped<TourSession>();

var app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

namespace GuidedTour
{
    /// <summary>Marker type for <c>WebApplicationFactory</c>-based tests.</summary>
    public sealed class Entry { private Entry() { } }
}
