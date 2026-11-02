package main

import "fmt"

type Asset struct {
	Name        string
	Type        string
	Environment string
}

func (asset Asset) Summary() string {
	return fmt.Sprintf("%s [%s] - %s", asset.Name, asset.Type, asset.Environment)
}

func main() {
	asset := Asset{
		Name:        "api.example.com",
		Type:        "service",
		Environment: "production",
	}

	fmt.Println(asset.Summary())
}
