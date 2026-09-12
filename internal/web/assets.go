package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"

	"github.com/AhmadShamli/Funnel/internal/models"
	"github.com/AhmadShamli/Funnel/internal/version"
)

//go:embed static/* templates/*
var EmbeddedFS embed.FS

// TemplateManager parses and executes embedded templates.
type TemplateManager struct {
	templates map[string]*template.Template
}

// NewTemplateManager initializes and pre-parses HTML templates.
func NewTemplateManager() (*TemplateManager, error) {
	tm := &TemplateManager{
		templates: make(map[string]*template.Template),
	}

	funcMap := template.FuncMap{
		"appVersion": func() string { return version.Version },
		"appName":    func() string { return version.AppName },
		"author":     func() string { return version.Author },
		"repoURL":    func() string { return version.RepositoryURL },
		"hasPortGroup": func(pgs []models.PortGroup, id int64) bool {
			for _, pg := range pgs {
				if pg.ID == id {
					return true
				}
			}
			return false
		},
	}

	pages := []struct {
		name  string
		files []string
	}{
		{"visitor_index", []string{"templates/layout.html", "templates/visitor_index.html"}},
		{"visitor_status", []string{"templates/layout.html", "templates/visitor_status.html"}},
		{"setup", []string{"templates/layout.html", "templates/setup.html"}},
		{"admin_login", []string{"templates/layout.html", "templates/admin_login.html"}},
		{"admin_dashboard", []string{"templates/admin_layout.html", "templates/admin_dashboard.html"}},
		{"admin_keys", []string{"templates/admin_layout.html", "templates/admin_keys.html"}},
		{"admin_port_groups", []string{"templates/admin_layout.html", "templates/admin_port_groups.html"}},
		{"admin_networks", []string{"templates/admin_layout.html", "templates/admin_networks.html"}},
		{"admin_open_ports", []string{"templates/admin_layout.html", "templates/admin_open_ports.html"}},
		{"admin_grants", []string{"templates/admin_layout.html", "templates/admin_grants.html"}},
		{"admin_firewalls", []string{"templates/admin_layout.html", "templates/admin_firewalls.html"}},
		{"admin_audit", []string{"templates/admin_layout.html", "templates/admin_audit.html"}},
		{"admin_settings", []string{"templates/admin_layout.html", "templates/admin_settings.html"}},
		{"admin_users", []string{"templates/admin_layout.html", "templates/admin_users.html"}},
	}

	for _, page := range pages {
		baseName := filepath.Base(page.files[0])
		tmpl, err := template.New(baseName).Funcs(funcMap).ParseFS(EmbeddedFS, page.files...)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", page.name, err)
		}
		tm.templates[page.name] = tmpl
	}

	return tm, nil
}

// Render renders a specific template name with data.
func (tm *TemplateManager) Render(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, ok := tm.templates[name]
	if !ok {
		return fmt.Errorf("template %s not found", name)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if tmpl.Lookup("admin_layout") != nil {
		return tmpl.ExecuteTemplate(w, "admin_layout", data)
	}
	if tmpl.Lookup("layout") != nil {
		return tmpl.ExecuteTemplate(w, "layout", data)
	}
	return tmpl.Execute(w, data)
}

// StaticFileServer returns an http.Handler serving the embedded static directory.
func StaticFileServer() http.Handler {
	sub, err := fs.Sub(EmbeddedFS, "static")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
