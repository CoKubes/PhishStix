using System.Text.Json.Serialization;
using System.Collections.Generic;

namespace PhishingAnalyzerFrontend.Models
{
    public class AnalysisResult
    {
        [JsonPropertyName("url")]
        public string? Url { get; set; }

        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }

        [JsonPropertyName("reasons")]
        public List<string>? Reasons { get; set; }
    }
}
