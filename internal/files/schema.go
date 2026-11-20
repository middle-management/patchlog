package files

import (
	_ "embed"

	"github.com/middle-management/patchlog/internal/jsonv"
)

// SchemaResource is where tools look for the file schema (§H.2, §H.3):
// GET /{ns}?facet[/folder]={path}&schema=/r/schemas/file&sort=/name.
const SchemaResource = "/r/schemas/file"

// schemaJSON is the file schema (§H.2): a file or folder of a file tree is
// a document { $schema, folder, name, content? }, content the file (a
// folder has none). /folder and /name are facets, /name a sort key too
// (§A.2), so a folder is listed by the index. A title's characters are
// checked by the pattern and "not", its byte length by the tool (§H.2
// "Titles"); a folder path is / or /-separated titles.
//
//go:embed schema.json
var schemaJSON []byte

// SchemaJSON is the file schema's text, to be created at SchemaResource.
func SchemaJSON() []byte { return append([]byte(nil), schemaJSON...) }

// Schema is the file schema, parsed (jsonv values).
func Schema() map[string]any {
	v, err := jsonv.Parse(schemaJSON)
	if err != nil {
		panic("files: schema.json: " + err.Error())
	}
	return v.(map[string]any)
}
