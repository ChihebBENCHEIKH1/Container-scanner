package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"container-scanner/internal/api"
	"container-scanner/internal/scanners"
	"container-scanner/internal/utils"

	"github.com/fatih/color"
)

func runScan(targetImage string, jsonOutput string) {
	cli, err := utils.GetDockerClient()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	img, err := utils.GetImage(cli, targetImage)
	if err != nil {
		color.Red("Could not find or pull image %s: %v", targetImage, err)
		os.Exit(1)
	}

	color.Green("Starting scan for %s (ID: %s)", targetImage, img.ID[:12])

	findings := []scanners.Finding{}
	
	// Register scanners
	activeScanners := []scanners.Scanner{
		&scanners.ConfigScanner{},
		scanners.NewSastScanner(),
		&scanners.DastScanner{},
	}

	// Inspect image for ConfigScanner
	inspect, err := cli.ImageInspect(context.Background(), img.ID)
	if err != nil {
		fmt.Printf("Warning: Could not inspect image: %v\n", err)
	}

	ctx := map[string]interface{}{
		"client":  cli,
		"inspect": inspect,
	}

	for _, scanner := range activeScanners {
		fmt.Printf("Running %s...\n", scanner.Name())
		results, err := scanner.Scan(img, ctx)
		if err != nil {
			color.Red("Error running %s: %v", scanner.Name(), err)
			continue
		}
		findings = append(findings, results...)
	}

	printReport(findings, jsonOutput)
}

func printReport(findings []scanners.Finding, jsonOutput string) {
	if jsonOutput != "" {
		data, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			fmt.Printf("Error generating JSON: %v\n", err)
			return
		}
		err = os.WriteFile(jsonOutput, data, 0644)
		if err != nil {
			fmt.Printf("Error saving report: %v\n", err)
			return
		}
		color.Green("Report saved to %s", jsonOutput)
		return
	}

	if len(findings) == 0 {
		color.Green("\nNo issues found!")
		return
	}

	fmt.Printf("\n%-15s %-10s %-30s %s\n", "Scanner", "Severity", "Issue", "Details")
	fmt.Println(strings.Repeat("-", 80))

	for _, f := range findings {
		severityColor := color.New(color.FgWhite)
		switch f.Severity {
		case "HIGH":
			severityColor = color.New(color.FgRed)
		case "MEDIUM":
			severityColor = color.New(color.FgYellow)
		case "LOW":
			severityColor = color.New(color.FgBlue)
		}
		
		fmt.Printf("%-15s ", f.Scanner)
		severityColor.Printf("%-10s ", f.Severity)
		fmt.Printf("%-30s %s\n", f.Description, f.Details)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		jsonPtr := scanCmd.String("json", "", "Output report to JSON file")
		scanCmd.Parse(os.Args[2:])

		if scanCmd.NArg() < 1 {
			fmt.Println("Usage: container-scanner scan <image> [--json <file>]")
			os.Exit(1)
		}
		targetImage := scanCmd.Arg(0)
		runScan(targetImage, *jsonPtr)

	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		portPtr := serveCmd.String("port", "8080", "Port to run the server on")
		serveCmd.Parse(os.Args[2:])

		fmt.Printf("Starting web interface on port %s...\n", *portPtr)
		if err := api.StartServer(*portPtr); err != nil {
			fmt.Printf("Error starting server: %v\n", err)
			os.Exit(1)
		}

	case "help":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Container Scanner - Go Edition")
	fmt.Println("\nUsage:")
	fmt.Println("  container-scanner <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  scan    Perform a one-time scan of a Docker image")
	fmt.Println("  serve   Start the web interface")
	fmt.Println("  help    Show this help message")
	fmt.Println("\nUse 'container-scanner <command> --help' for more information on a command.")
}
