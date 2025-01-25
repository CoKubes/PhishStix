# PhishStix
PhishStix is an interactive tool designed to analyze URLs for potential phishing risks. By combining various detection techniques, including keyword analysis, redirect chain evaluation, HTML content examination, and domain reputation checks, PhishStix provides users with a comprehensive risk score and detailed reasoning for each analyzed URL.

## TODO:
I still have some bugs to fix and want to add many more features to add. I will put specific TODOs in the subfolders. 

### **Features**

- **URL Risk Scoring**  
 - Assigns a risk score to URLs based on multiple phishing detection criteria.  
  - Highlights potential issues such as suspicious keywords, excessive redirects, and domain impersonation.

- **Google Safe Browsing Integration**  
  - Leverages the Google Safe Browsing API to flag URLs reported as malicious.

- **Redirect Chain Analysis**  
  - Traces the redirect path of a URL to detect excessive or unusual redirections.

- **HTML Content Inspection**  
  - Analyzes the HTML structure of websites for phishing indicators, such as suspicious links or forms.

- **Domain Reputation and Similarity Checks**  
  - Compares domains to trusted sources to identify typosquatting or spoofing.

- **Cross-Platform Compatibility**  
  - Built with a C# ASP.NET Core frontend and a Python Flask backend, ensuring high scalability and performance.

- **User-Friendly Interface**  
  - Provides a clean and modern UI for entering URLs and viewing results with detailed explanations.

- **Secure by Design**  
  - Employs secure coding practices, including API key protection via environment variables and server-side validation.

---

### **Technology Stack**

- **Frontend**:  
  - ASP.NET Core MVC  
  - Implements a responsive, user-friendly interface using Bootstrap for styling and Razor views for dynamic content rendering.  
  - Static files (CSS, JavaScript, and images) are managed through the `wwwroot` folder.

- **Backend**:  
  - Python Flask  
  - Processes URL analysis requests and returns detailed results through a REST API.  
  - Modularized architecture with separate files for URL checks, domain checks, and HTML analysis.

- **APIs and Libraries**:  
  - **Google Safe Browsing API**: Detects URLs flagged as unsafe.  
  - **tldextract**: Extracts and analyzes domain components.  
  - **Levenshtein Distance**: Measures domain similarity for typosquatting detection.  
  - **BeautifulSoup**: Parses and analyzes HTML content for phishing indicators.

- **Environment Management**:  
  - Dependencies are managed using virtual environments (`venv` for Python) and `dotnet` for ASP.NET.


```
PhishStix/
│
├── backend/
│   ├── run.py                  # Main Flask application entry point
│   ├── config.py               # Global variables and environment config
│   ├── utils/                  # Folder for modularized backend utilities
│   │   ├── url_checks.py
│   │   ├── domain_checks.py
│   │   ├── html_analysis.py
│   ├── phishing_analyzer.log   # Log file for backend activities
│   ├── requirements.txt        # Python dependencies
│   ├── venv/                   # Virtual environment folder
│   └── README.md
│
├── frontend/                     # C# frontend
│   ├── PhishingAnalyzerFrontend/ # ASP.NET Core project
│   │   ├── Controllers/          # MVC Controllers
│   │   ├── Views/                # Razor Views or Blazor Pages
│   │   ├── wwwroot/              # Static files (CSS, JS, etc.)
│   │   ├── PhishingAnalyzerFrontend.csproj
│   │   └── Program.cs            # Entry point for the frontend
│   └── README.md
│
├── docs/                         # Documentation
│   ├── api.md                    # API documentation
│   ├── design.md                 # Design and architecture notes
│   └── features.md               # Planned features and roadmap
│
├── scripts/                      # Utility scripts
│   ├── setup.sh                  # Script to set up the project locally
│   ├── start.sh                  # Script to start the backend and frontend
│
├── .gitignore                    # Git ignore file
├── README.md                     # Project overview
└── LICENSE                       # License for the project
```
