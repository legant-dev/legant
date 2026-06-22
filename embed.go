package legant

import "embed"

//go:embed migrations/*.sql
var MigrationsFS embed.FS

//go:embed web/templates/*.html
var TemplatesFS embed.FS
