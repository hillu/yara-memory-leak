package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"yara-memory-leak/go-yara-4.1.0"
)

var (
	scanner     Scanner
	tmpRulePath = "./rules"
)

type Scanner struct {
	Rules     *yara.Rules
	rulesPath string
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

	})
	http.HandleFunc("/i", func(w http.ResponseWriter, r *http.Request) {
		New(tmpRulePath)
	})
	http.ListenAndServe(":3000", nil)
}

func New(rulesPath string) (scanner *Scanner, err error) {
	scanner = &Scanner{
		rulesPath: rulesPath, // set yara rules path (a directory)
	}
	err = scanner.Init()
	if err != nil {
		return scanner, err
	}
	return scanner, err
}

// Compile will compile the provided Yara rules in a Rules object.
func (s *Scanner) Compile() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	rulesStat, _ := os.Stat(s.rulesPath)
	if rulesStat.Mode().IsDir() {
		err = filepath.Walk(s.rulesPath, func(filePath string, fileInfo os.FileInfo, err error) error {
			fileName := fileInfo.Name()
			if (path.Ext(fileName) == ".yar") || (path.Ext(fileName) == ".yara") {
				rulesFile, _ := os.Open(filePath)
				defer rulesFile.Close()
				err = compiler.AddFile(rulesFile, "")
				if err != nil {
					return err
				}
			}
			return nil
		})
	}

	// Collect and compile Yara rules.
	s.Rules, err = compiler.GetRules()
	if err != nil {
		return err
	}

	return nil
}

// Init instantiates a new Yara scanner.
func (s *Scanner) Init() error {
	fmt.Println("Loading Yara rules...")
	if s.rulesPath != "" {
		if _, err := os.Stat(s.rulesPath); os.IsNotExist(err) {
			return errors.New("The specified rules path does not exist")
		}
		return s.Compile()
	}

	return nil
}

// ScanFile scans a file path with the provided Yara rules.
func (s *Scanner) ScanFile(filePath string) (yara.MatchRules, error) {
	var matches yara.MatchRules

	// Check if the executable file exists.
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return matches, errors.New("Scanned file does not exist")
	}

	// Scan the file.
	err := s.Rules.ScanFile(filePath, 1, 60, &matches)
	if err != nil {
		return matches, err
	}

	// Return any results.
	return matches, nil
}
