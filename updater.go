package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var timesSeen = make(map[string]int)

// Update downloads all the blocklists and imports them into the database
func update(blockCache *MemoryBlockCache, exceptCache *MemoryBlockCache, wlist []string, blist []string, sources []string) error {
	if _, err := os.Stat("sources"); os.IsNotExist(err) {
		if err := os.Mkdir("sources", 0700); err != nil {
			return fmt.Errorf("error creating sources directory: %s", err)
		}
	}

	for _, entry := range wlist {
		exceptCache.Set(entry, true)
	}

	for _, entry := range blist {
		err := blockCache.Set(entry, true)
		if err != nil {
			logger.Critical(err)
		}
	}

	if err := fetchSources(sources); err != nil {
		return fmt.Errorf("error fetching sources: %s", err)
	}

	return nil
}

func downloadFile(uri string, name string) error {
	filePath := filepath.FromSlash(fmt.Sprintf("sources/%s", name))

	output, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %s", err)
	}

	defer func() {
		if err := output.Close(); err != nil {
			logger.Criticalf("Error closing file: %s\n", err)
		}
	}()

	response, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("error downloading source: %s", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(response.Body)

	if _, err := io.Copy(output, response.Body); err != nil {
		return fmt.Errorf("error copying output: %s", err)
	}

	return nil
}

func fetchSources(sources []string) error {
	var wg sync.WaitGroup

	for _, uri := range sources {
		wg.Add(1)

		u, _ := url.Parse(uri)
		host := u.Host
		timesSeen[host] = timesSeen[host] + 1
		fileName := fmt.Sprintf("%s.%d.list", host, timesSeen[host])

		go func(uri string, name string) {
			logger.Debugf("fetching source %s\n", uri)
			if err := downloadFile(uri, name); err != nil {
				fmt.Println(err)
			}

			wg.Done()
		}(uri, fileName)
	}

	wg.Wait()

	return nil
}

// UpdateBlockCache updates the BlockCache
func updateBlockCache(blockCache *MemoryBlockCache, exceptCache *MemoryBlockCache, sourceDirs []string) error {
	logger.Debugf("loading blocked domains from %d locations...\n", len(sourceDirs))

	for _, dir := range sourceDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			logger.Errorf("directory %s not found, skipping\n", dir)
			continue
		}

		err := filepath.Walk(dir, func(path string, f os.FileInfo, _ error) error {
			if !f.IsDir() {
				fileName := filepath.FromSlash(path)

				if err := parseHostFile(fileName, blockCache, exceptCache); err != nil {
					return fmt.Errorf("error parsing hostfile %s", err)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("error walking location %s", err)
		}
	}

	logger.Debugf("%d domains loaded from sources\n", blockCache.Length())

	return nil
}

func parseHostFile(fileName string, blockCache *MemoryBlockCache, exceptCache *MemoryBlockCache) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("error opening file: %s", err)
	}

	defer func() {
		if err := file.Close(); err != nil {
			logger.Criticalf("Error closing file: %s\n", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)
		isException := strings.HasPrefix(line, "!")

		if len(line) > 0 {
			fields := strings.Fields(line)

			if len(fields) > 1 {
				line = fields[1]
			} else {
				line = fields[0]
			}

			if isException {
				if !exceptCache.Exists(line) {
					err := exceptCache.Set(line[1:], true)
					if err != nil {
						logger.Critical(err)
					}
				}
			} else {
				if !blockCache.Exists(line) && !exceptCache.Exists(line) {
					err := blockCache.Set(line, true)
					if err != nil {
						logger.Critical(err)
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning hostfile: %s", err)
	}

	return nil
}

// PerformUpdate updates the block cache by building a new one and swapping
// it for the old cache.
func PerformUpdate(config *Config, forceUpdate bool) (*MemoryBlockCache, *MemoryBlockCache) {
	newBlockCache := &MemoryBlockCache{Backend: make(map[string]bool), Special: make(map[string]*regexp.Regexp)}
	newExceptCache := &MemoryBlockCache{Backend: make(map[string]bool)}
	if _, err := os.Stat("lists"); os.IsNotExist(err) || forceUpdate {
		if err := update(newBlockCache, newExceptCache, config.Whitelist, config.Blocklist, config.Sources); err != nil {
			logger.Fatal(err)
		}
	}
	if err := updateBlockCache(newBlockCache, newExceptCache, config.SourceDirs); err != nil {
		logger.Fatal(err)
	}

	return newBlockCache, newExceptCache
}
