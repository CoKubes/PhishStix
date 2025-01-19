using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using PhishingAnalyzerFrontend.Models;

public class HomeController : Controller
{
    private readonly HttpClient _httpClient;

    public HomeController(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient();
    }

    [HttpGet]
    public IActionResult Index()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> AnalyzeUrl(string url)
    {
        // Prepare request body for Python backend
        var requestBody = new { url = url };
        var json = JsonSerializer.Serialize(requestBody);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        // Send POST request to the backend
        var response = await _httpClient.PostAsync("http://127.0.0.1:5000/analyze_url", content);
        var resultJson = await response.Content.ReadAsStringAsync();

        // Log the raw response for debugging
        Console.WriteLine("Backend Response: " + resultJson);

        // Deserialize response into AnalysisResult
        var result = JsonSerializer.Deserialize<AnalysisResult>(resultJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        // Pass the result to the view
        ViewBag.AnalysisResult = result;

        return View("Index");
    }
}
