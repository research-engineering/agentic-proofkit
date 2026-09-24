package publicapi

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/evanw/esbuild/pkg/api"
)

type runtimeExportMetafile struct {
	Inputs map[string]struct {
		Format string `json:"format"`
	} `json:"inputs"`
	Outputs map[string]struct {
		EntryPoint string   `json:"entryPoint"`
		Exports    []string `json:"exports"`
	} `json:"outputs"`
}

func collectRuntimeExports(source string, extension string) ([]string, error) {
	sourcefile := "entry" + extension
	result := api.Build(api.BuildOptions{
		Stdin: &api.StdinOptions{
			Contents:   source,
			Loader:     api.LoaderTS,
			Sourcefile: sourcefile,
		},
		Bundle:      false,
		Format:      api.FormatESModule,
		LogLevel:    api.LogLevelSilent,
		Metafile:    true,
		Outfile:     "entry.js",
		Platform:    api.PlatformNeutral,
		Target:      api.ESNext,
		TsconfigRaw: "{}",
		Write:       false,
	})
	if len(result.Errors) != 0 {
		return nil, unsupportedTypeScriptSourceGrammar("TypeScript parser rejected source")
	}
	var metadata runtimeExportMetafile
	if err := json.Unmarshal([]byte(result.Metafile), &metadata); err != nil || len(metadata.Outputs) != 1 {
		return nil, fmt.Errorf("TypeScript public API parser did not produce one export inventory")
	}
	if len(metadata.Inputs) != 1 {
		return nil, fmt.Errorf("TypeScript public API parser input inventory is invalid")
	}
	inputFormat := metadata.Inputs[sourcefile].Format
	for _, output := range metadata.Outputs {
		if output.EntryPoint != sourcefile {
			return nil, fmt.Errorf("TypeScript public API parser output has an unexpected entrypoint")
		}
		if (inputFormat == "" || inputFormat == "cjs") && (len(output.Exports) == 0 || len(output.Exports) == 1 && output.Exports[0] == "default") {
			return []string{}, nil
		}
		if inputFormat != "esm" {
			return nil, unsupportedTypeScriptSourceGrammar("unsupported module format")
		}
		names := append([]string{}, output.Exports...)
		sort.Strings(names)
		for index, name := range names {
			if index > 0 && names[index-1] == name {
				return nil, fmt.Errorf("TypeScript public API parser output contains duplicate exports")
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("TypeScript public API parser output is missing")
}
