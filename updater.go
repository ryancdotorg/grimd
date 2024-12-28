package main

import (
	"crypto/sha256"
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

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

func makeRequest(uri string, filePath string) (func() (*http.Response, error), error) {
	client := &http.Client{}
	request, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("error downloading source: %s %s", uri, err)
	}

	current, err := os.ReadFile(filePath)
	if err == nil {
		re := regexp.MustCompile("^# (Date|ETag): ([^\r\n]+)[\r\n]*")
		for _, line := range strings.Split(string(current), "\n") {
			if line == "" {
				break
			} else if m := re.FindStringSubmatch(line); len(m) > 0 {
				if m[1] == "ETag" {
					request.Header.Add("If-None-Match", m[2])
				} else if m[1] == "Date" {
					request.Header.Add("If-Modified-Since", m[2])
				}
			}
		}
	} else if !os.IsNotExist(err) {
		logger.Warningf("Error reading file: %s", err)
	}

	return func() (*http.Response, error) {
		return client.Do(request)
	}, nil
}

func downloadFile(uri string, name string) error {
	filePath := filepath.FromSlash(fmt.Sprintf("sources/%s", name))

	get, err := makeRequest(uri, filePath)
	if err != nil {
		return err
	}

	output, err := os.CreateTemp("sources", fmt.Sprintf("._temp.%s.*", name))
	if err != nil {
		return fmt.Errorf("error creating file: %s", err)
	}

	tempPath := filepath.FromSlash(output.Name())

	defer func() {
		if err := output.Close(); err != nil && err != fs.ErrClosed {
			logger.Criticalf("Error closing file: %s\n", err)
		}
	}()

	defer func() {
		if _, err := os.Stat(tempPath); err != nil {
			if os.IsNotExist(err) {
				// assume the file was renamed
				return
			}
		}

		// remove the temp file if it hasn't been renamed
		if err := os.Remove(tempPath); err != nil {
			logger.Criticalf("Error removing temp file `%s`: %s\n", tempPath, err)
		}
	}()

	response, err := get()
	if err != nil {
		return fmt.Errorf("error downloading source: %s %s", uri, err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(response.Body)

	if response.StatusCode == 304 {
		logger.Infof("Not modified: %s", uri)
		return nil
	} else if response.StatusCode != 200 {
		return fmt.Errorf("error downloading source: %s %s", uri, response.Status)
	}

	downloadTime := time.Now()
	header := fmt.Sprintf(
		"# Downloaded at %s from %s\n",
		downloadTime.Format(time.RFC3339), uri,
	)
	output.WriteString(header)

	// save etag or date so we don't have to re-download unchanged files
	// NOTE: we prefer ETag over Date - in theory if both the If-None-Match
	// header with an ETag and If-Modified-Since with a Date are set, the
	// latter is supposed to be ignored, but not all servers work like that.
	if etag := response.Header.Get("ETag"); etag != "" {
		output.WriteString(fmt.Sprintf("# ETag: %s\n", etag))
	} else if date := response.Header.Get("Date"); date != "" {
		output.WriteString(fmt.Sprintf("# Date: %s\n", date))
	}

	output.WriteString("\n")

	if _, err := io.Copy(output, response.Body); err != nil {
		return fmt.Errorf("error copying output: %s", err)
	}

	if err := output.Close(); err != nil {
		logger.Criticalf("Error closing file: %s\n", err)
	}

	if err := os.Chmod(tempPath, 0o644); err != nil {
		logger.Warningf("error chmod temp file: %s", err)
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("error renaming output: %s", err)
	}

	return nil
}

func fetchSources(sources []string) error {
	var wg sync.WaitGroup

	for _, uri := range sources {
		wg.Add(1)

		// get the first 12 bytes of the sha256 hash of the uri
		hash := sha256.New()
		hash.Write([]byte(uri))
		urihash := fmt.Sprintf("%s", hash.Sum(nil)[:12])

		u, _ := url.Parse(uri)
		host := u.Host
		fileName := fmt.Sprintf("%s.%x.list", host, urihash)

		// TODO: create a Client and reuse it for all the requests
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
			if !(f.IsDir() || strings.HasPrefix(f.Name(), "._temp.")) {
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
				// verify this is something that ought to be blocked
				if fields[0] == "127.0.0.1" || fields[0] == "0.0.0.0" {
					line = fields[1]
				} else {
					continue
				}
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
