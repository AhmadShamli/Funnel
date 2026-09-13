package web

import (
	"fmt"
	"html"
	"html/template"
	"regexp"
	"strconv"
	"strings"
)

var (
	reCodeBlock     = regexp.MustCompile(`(?is)\[code\](.*?)\[/code\]`)
	reBold          = regexp.MustCompile(`(?is)\[b\](.*?)\[/b\]`)
	reItalic        = regexp.MustCompile(`(?is)\[i\](.*?)\[/i\]`)
	reUnderline     = regexp.MustCompile(`(?is)\[u\](.*?)\[/u\]`)
	reStrike        = regexp.MustCompile(`(?is)\[(?:s|strike|del)\](.*?)\[/(?:s|strike|del)\]`)
	reURLParam      = regexp.MustCompile(`(?is)\[url=([^\]]+)\](.*?)\[/url\]`)
	reURLSimple     = regexp.MustCompile(`(?is)\[url\](.*?)\[/url\]`)
	reImg           = regexp.MustCompile(`(?is)\[img\](.*?)\[/img\]`)
	reColor         = regexp.MustCompile(`(?is)\[color=([#a-zA-Z0-9]+)\](.*?)\[/color\]`)
	reSize          = regexp.MustCompile(`(?is)\[size=([a-zA-Z0-9.%]+)\](.*?)\[/size\]`)
	reQuoteAuthor   = regexp.MustCompile(`(?is)\[quote=(?:&quot;|"|'|&amp;quot;|&#34;|&#39;)?([^\]"'\&]+?)(?:&quot;|"|'|&amp;quot;|&#34;|&#39;)?\](.*?)\[/quote\]`)
	reQuoteSimple   = regexp.MustCompile(`(?is)\[quote\](.*?)\[/quote\]`)
	reCenter        = regexp.MustCompile(`(?is)\[center\](.*?)\[/center\]`)
	reRight         = regexp.MustCompile(`(?is)\[right\](.*?)\[/right\]`)
	reList          = regexp.MustCompile(`(?is)\[list(?:=([1aAiI]))?\](.*?)\[/list\]`)
	reListSplit     = regexp.MustCompile(`(?i)\[\*\]`)
	reSafeColorHex  = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
	reSafeColorName = regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
	reValidScheme   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*$`)
)

// sanitizeURL strips wrapping quotes and HTML entities from a raw URL.
func sanitizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	unescaped := html.UnescapeString(rawURL)
	for {
		changed := false
		for _, q := range []string{"\"", "'", "&#34;", "&quot;", "&#39;"} {
			if strings.HasPrefix(unescaped, q) {
				unescaped = strings.TrimPrefix(unescaped, q)
				changed = true
			}
			if strings.HasSuffix(unescaped, q) {
				unescaped = strings.TrimSuffix(unescaped, q)
				changed = true
			}
		}
		unescaped = strings.TrimSpace(unescaped)
		if !changed {
			break
		}
	}
	return unescaped
}

// isSafeURL checks whether a URL is safe to render as a link or image source.
func isSafeURL(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false
	}
	unescaped := sanitizeURL(rawURL)

	// Reject any control characters, newlines, or tabs
	for i := 0; i < len(unescaped); i++ {
		if unescaped[i] < 32 || unescaped[i] == 127 {
			return false
		}
	}

	// Relative URLs
	if strings.HasPrefix(unescaped, "/") || strings.HasPrefix(unescaped, "#") {
		return true
	}

	// Colon check for scheme
	colonIdx := strings.Index(unescaped, ":")
	if colonIdx == -1 {
		return false
	}

	scheme := strings.ToLower(strings.TrimSpace(unescaped[:colonIdx]))
	if !reValidScheme.MatchString(scheme) {
		return false
	}

	// Strictly block dangerous pseudo-protocols that can execute client-side scripts or access local files
	blockedSchemes := map[string]bool{
		"javascript": true,
		"data":       true,
		"vbscript":   true,
		"file":       true,
	}
	if blockedSchemes[scheme] {
		return false
	}

	return true
}

// parseBBCodeSize maps size values (1-7, percentages, or CSS units) to safe CSS font-size values.
func parseBBCodeSize(sizeVal string) string {
	sizeVal = strings.TrimSpace(strings.ToLower(sizeVal))
	if sizeVal == "" {
		return ""
	}
	sizeVal = strings.Trim(sizeVal, "\"'")

	// Standard numeric sizes 1-7
	if n, err := strconv.Atoi(sizeVal); err == nil {
		if n >= 1 && n <= 7 {
			sizes := map[int]string{
				1: "0.75rem", 2: "0.85rem", 3: "1rem",
				4: "1.15rem", 5: "1.3rem", 6: "1.5rem", 7: "1.85rem",
			}
			return sizes[n]
		}
		// Percentage sizes without % symbol (e.g. 150 -> 150%, 200 -> 200%)
		if n >= 10 {
			if n > 300 {
				n = 300
			}
			if n < 50 {
				n = 50
			}
			return fmt.Sprintf("%d%%", n)
		}
	}

	// Percentage with % (e.g. 150%)
	if strings.HasSuffix(sizeVal, "%") {
		numStr := strings.TrimSuffix(sizeVal, "%")
		if n, err := strconv.Atoi(numStr); err == nil {
			if n > 300 {
				n = 300
			}
			if n < 50 {
				n = 50
			}
			return fmt.Sprintf("%d%%", n)
		}
	}

	// Pixels (e.g. 18px)
	if strings.HasSuffix(sizeVal, "px") {
		numStr := strings.TrimSuffix(sizeVal, "px")
		if n, err := strconv.Atoi(numStr); err == nil {
			if n > 36 {
				n = 36
			}
			if n < 9 {
				n = 9
			}
			return fmt.Sprintf("%dpx", n)
		}
	}

	// Points (e.g. 14pt)
	if strings.HasSuffix(sizeVal, "pt") {
		numStr := strings.TrimSuffix(sizeVal, "pt")
		if n, err := strconv.Atoi(numStr); err == nil {
			if n > 28 {
				n = 28
			}
			if n < 7 {
				n = 7
			}
			return fmt.Sprintf("%dpt", n)
		}
	}

	// Rem / em (e.g. 1.5rem)
	if strings.HasSuffix(sizeVal, "rem") || strings.HasSuffix(sizeVal, "em") {
		isRem := strings.HasSuffix(sizeVal, "rem")
		numStr := strings.TrimSuffix(strings.TrimSuffix(sizeVal, "rem"), "em")
		if f, err := strconv.ParseFloat(numStr, 64); err == nil {
			if f > 2.5 {
				f = 2.5
			}
			if f < 0.5 {
				f = 0.5
			}
			unit := "em"
			if isRem {
				unit = "rem"
			}
			return fmt.Sprintf("%.2f%s", f, unit)
		}
	}

	return ""
}

// RenderBBCode converts BBCode or plain text to safe, sanitized HTML.
func RenderBBCode(input string) template.HTML {
	if strings.TrimSpace(input) == "" {
		return ""
	}

	// 1. Extract and protect code blocks so their contents are never parsed as BBCode
	var codeBlocks []string
	placeholderPattern := "___FUNNEL_BBCODE_CODE_%d___"

	text := reCodeBlock.ReplaceAllStringFunc(input, func(m string) string {
		match := reCodeBlock.FindStringSubmatch(m)
		if len(match) > 1 {
			idx := len(codeBlocks)
			codeBlocks = append(codeBlocks, html.EscapeString(match[1]))
			return fmt.Sprintf(placeholderPattern, idx)
		}
		return m
	})

	// 2. Escape all remaining HTML entities to protect against XSS
	text = html.EscapeString(text)

	// Normalize newlines
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	// 3. Process nested inline & block BBCode tags (iterate to handle nesting)
	for i := 0; i < 6; i++ {
		orig := text

		text = reBold.ReplaceAllString(text, "<strong>$1</strong>")
		text = reItalic.ReplaceAllString(text, "<em>$1</em>")
		text = reUnderline.ReplaceAllString(text, "<u>$1</u>")
		text = reStrike.ReplaceAllString(text, "<s>$1</s>")
		text = reCenter.ReplaceAllString(text, `<div style="text-align: center;">$1</div>`)
		text = reRight.ReplaceAllString(text, `<div style="text-align: right;">$1</div>`)

		// Color tags
		text = reColor.ReplaceAllStringFunc(text, func(m string) string {
			match := reColor.FindStringSubmatch(m)
			if len(match) == 3 {
				colorVal := match[1]
				content := match[2]
				if reSafeColorHex.MatchString(colorVal) || reSafeColorName.MatchString(colorVal) {
					return fmt.Sprintf(`<span style="color: %s;">%s</span>`, html.EscapeString(colorVal), content)
				}
				return content
			}
			return m
		})

		// Size tags (1-7, percentages like 150/200, px, pt, rem, em)
		text = reSize.ReplaceAllStringFunc(text, func(m string) string {
			match := reSize.FindStringSubmatch(m)
			if len(match) == 3 {
				cssSize := parseBBCodeSize(match[1])
				content := match[2]
				if cssSize != "" {
					return fmt.Sprintf(`<span style="font-size: %s;">%s</span>`, cssSize, content)
				}
				return content
			}
			return m
		})

		// URLs with parameters (e.g. [url="minecraft://..."] or [url=http://...])
		text = reURLParam.ReplaceAllStringFunc(text, func(m string) string {
			match := reURLParam.FindStringSubmatch(m)
			if len(match) == 3 {
				targetURL := sanitizeURL(match[1])
				linkText := strings.Trim(match[2], "\r\n")
				if isSafeURL(targetURL) {
					return fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, html.EscapeString(targetURL), linkText)
				}
				return linkText
			}
			return m
		})

		// URLs simple (e.g. [url]https://...[/url])
		text = reURLSimple.ReplaceAllStringFunc(text, func(m string) string {
			match := reURLSimple.FindStringSubmatch(m)
			if len(match) == 2 {
				targetURL := sanitizeURL(match[1])
				if isSafeURL(targetURL) {
					return fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, html.EscapeString(targetURL), html.EscapeString(targetURL))
				}
				return html.EscapeString(targetURL)
			}
			return m
		})

		// Quotes
		text = reQuoteAuthor.ReplaceAllString(text, `<blockquote class="bbcode-quote"><div class="bbcode-quote-author">$1:</div>$2</blockquote>`)
		text = reQuoteSimple.ReplaceAllString(text, `<blockquote class="bbcode-quote">$1</blockquote>`)

		if text == orig {
			break
		}
	}

	// 4. Images
	text = reImg.ReplaceAllStringFunc(text, func(m string) string {
		match := reImg.FindStringSubmatch(m)
		if len(match) == 2 {
			imgURL := sanitizeURL(match[1])
			if isSafeURL(imgURL) {
				return fmt.Sprintf(`<img src="%s" alt="" style="max-width: 100%%; height: auto; border-radius: 4px;" />`, html.EscapeString(imgURL))
			}
		}
		return ""
	})

	// 5. Lists
	text = reList.ReplaceAllStringFunc(text, func(m string) string {
		match := reList.FindStringSubmatch(m)
		if len(match) == 3 {
			listType := match[1]
			inner := match[2]

			// Parse items
			var items []string
			parts := reListSplit.Split(inner, -1)
			if len(parts) > 1 {
				for i := 1; i < len(parts); i++ {
					cleaned := strings.TrimSpace(parts[i])
					if cleaned != "" {
						items = append(items, fmt.Sprintf("<li>%s</li>", cleaned))
					}
				}
			} else {
				lines := strings.Split(inner, "\n")
				for _, l := range lines {
					cleaned := strings.TrimSpace(l)
					if cleaned != "" {
						items = append(items, fmt.Sprintf("<li>%s</li>", cleaned))
					}
				}
			}

			listContent := strings.Join(items, "")
			if listType != "" {
				return fmt.Sprintf(`<ol class="bbcode-list">%s</ol>`, listContent)
			}
			return fmt.Sprintf(`<ul class="bbcode-list">%s</ul>`, listContent)
		}
		return m
	})

	// 6. Convert newlines to <br>
	text = strings.ReplaceAll(text, "\n", "<br>")

	// Clean up extra <br> around block-level elements
	blockCleanups := []struct {
		from string
		to   string
	}{
		{"<br><blockquote", "<blockquote"},
		{"</blockquote><br>", "</blockquote>"},
		{"<br><ul", "<ul"},
		{"</ul><br>", "</ul>"},
		{"<br><ol", "<ol"},
		{"</ol><br>", "</ol>"},
		{"<br><div", "<div"},
		{"</div><br>", "</div>"},
		{`<div style="text-align: center;"><br>`, `<div style="text-align: center;">`},
		{`<div style="text-align: right;"><br>`, `<div style="text-align: right;">`},
		{"<br></div>", "</div>"},
		{"<br><li", "<li"},
		{"</li><br>", "</li>"},
	}
	for _, bc := range blockCleanups {
		text = strings.ReplaceAll(text, bc.from, bc.to)
	}

	// 7. Restore code blocks
	for idx, codeContent := range codeBlocks {
		placeholder := fmt.Sprintf(placeholderPattern, idx)
		text = strings.ReplaceAll(text, "<br>"+placeholder, placeholder)
		text = strings.ReplaceAll(text, placeholder+"<br>", placeholder)

		renderedCode := fmt.Sprintf(`<pre class="bbcode-code"><code>%s</code></pre>`, codeContent)
		text = strings.ReplaceAll(text, placeholder, renderedCode)
	}

	return template.HTML(text)
}
