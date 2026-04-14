package admin

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pageTemplates maps page name → parsed template (layout + page content).
var pageTemplates map[string]*template.Template

// loginTemplate is the standalone login page.
var loginTemplate *template.Template

// setupWizardTemplate is the standalone multi-step setup wizard.
var setupWizardTemplate *template.Template

func init() {
	pageTemplates = make(map[string]*template.Template)
	pages := []string{
		"dashboard", "applications", "policies",
		"sessions", "logs", "authentication",
		"network", "certificates", "enrollment", "settings",
	}
	for _, p := range pages {
		t, err := template.ParseFS(templateFS,
			"templates/layout.html",
			"templates/pages/"+p+".html",
		)
		if err != nil {
			log.Fatalf("[ADMIN] failed to parse template %s: %v", p, err)
		}
		pageTemplates[p] = t
	}

	var err error
	loginTemplate, err = template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		log.Fatalf("[ADMIN] failed to parse login template: %v", err)
	}

	setupWizardTemplate, err = template.ParseFS(templateFS, "templates/setup-wizard.html")
	if err != nil {
		log.Fatalf("[ADMIN] failed to parse setup-wizard template: %v", err)
	}
}

// serveStaticFile serves embedded static assets (CSS, JS).
func serveStaticFile(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		http.Error(w, "static files not available", http.StatusInternalServerError)
		return
	}
	http.StripPrefix("/static/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

// servePage renders a page using the layout template with the given page name.
func servePage(w http.ResponseWriter, page string) {
	t, ok := pageTemplates[page]
	if !ok {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]string{"Page": page}
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("[ADMIN] template error (%s): %v", page, err)
		http.Error(w, "template rendering error", http.StatusInternalServerError)
	}
}

// serveLogin renders the standalone login page.
func serveLogin(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTemplate.Execute(w, nil); err != nil {
		log.Printf("[ADMIN] login template error: %v", err)
		http.Error(w, "template rendering error", http.StatusInternalServerError)
	}
}

// serveSetupWizard renders the standalone multi-step setup wizard.
func serveSetupWizard(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := setupWizardTemplate.Execute(w, nil); err != nil {
		log.Printf("[ADMIN] setup-wizard template error: %v", err)
		http.Error(w, "template rendering error", http.StatusInternalServerError)
	}
}

// setupState holds the progress flags needed for routing decisions.
type setupState struct {
	Completed bool
	HasAdmin  bool
}

// handleUIRequest is the main UI handler for all non-API routes.
// ss carries setup progress so the template layer can gate access.
func handleUIRequest(w http.ResponseWriter, r *http.Request, ss setupState) {
	path := strings.TrimPrefix(r.URL.Path, "/")

	// Serve static assets (always allowed)
	if strings.HasPrefix(r.URL.Path, "/static/") {
		serveStaticFile(w, r)
		return
	}

	// API routes should not reach here
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}

	// ── Setup page routing ──────────────────────────────
	// All /setup/* paths serve the unified wizard (JS handles step state)
	if path == "setup" || strings.HasPrefix(path, "setup/") {
		if ss.Completed {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		serveSetupWizard(w)
		return
	}

	// If setup is NOT complete, redirect everything to the setup wizard
	if !ss.Completed {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	// Login page
	if path == "login" {
		serveLogin(w)
		return
	}

	// Default to dashboard
	if path == "" || path == "/" {
		path = "dashboard"
	}

	// Redirect old URLs to new names
	redirects := map[string]string{
		"resources":    "applications",
		"cgnat":        "network",
		"config":       "settings",
		"policies":     "settings",
		"sessions":     "settings",
		"logs":         "settings",
		"network":      "settings",
		"certificates": "settings",
		"enrollment":   "settings",
	}
	if newPath, ok := redirects[path]; ok {
		http.Redirect(w, r, "/"+newPath, http.StatusFound)
		return
	}

	// Valid pages
	validPages := map[string]bool{
		"dashboard": true, "applications": true, "settings": true, "authentication": true,
	}

	if validPages[path] {
		servePage(w, path)
		return
	}

	// Unknown → dashboard
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
