package publicapi

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/evanw/esbuild/pkg/api"
)

type runtimeExportMetafile struct {
	Outputs map[string]struct {
		EntryPoint string   `json:"entryPoint"`
		Exports    []string `json:"exports"`
	} `json:"outputs"`
}

func collectRuntimeExports(source string) ([]string, error) {
	result := api.Build(api.BuildOptions{
		Stdin: &api.StdinOptions{
			Contents:   source,
			Loader:     api.LoaderTS,
			Sourcefile: "entry.ts",
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
	for _, output := range metadata.Outputs {
		if output.EntryPoint != "entry.ts" {
			return nil, fmt.Errorf("TypeScript public API parser output has an unexpected entrypoint")
		}
		names := append([]string{}, output.Exports...)
		sort.Strings(names)
		for index := 1; index < len(names); index++ {
			if names[index-1] == names[index] {
				return nil, fmt.Errorf("TypeScript public API parser output contains duplicate exports")
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("TypeScript public API parser output is missing")
}
