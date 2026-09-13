package web

import (
	"fmt"
	"html"
	"html/template"
	"net/url"
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
	reSize          = regexp.MustCompile(`(?is)\[size=([a-zA-Z0-9%]+)\](.*?)\[/size\]`)
	reQuoteAuthor   = regexp.MustCompile(`(?is)\[quote=(?:&quot;|"|'|&amp;quot;)?([^\]"'\&]+?)(?:&quot;|"|'|&amp;quot;)?\](.*?)\[/quote\]`)
	reQuoteSimple   = regexp.MustCompile(`(?is)\[quote\](.*?)\[/quote\]`)
	reCenter        = regexp.MustCompile(`(?is)\[center\](.*?)\[/center\]`)
	reRight         = regexp.MustCompile(`(?is)\[right\](.*?)\[/right\]`)
	reList          = regexp.MustCompile(`(?is)\[list(?:=([1aAiI]))?\](.*?)\[/list\]`)
	reListSplit     = regexp.MustCompile(`(?i)\[\*\]`)
	reSafeColorHex  = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
	reSafeColorName = regexp.MustCompile(`^[a-zA-Z]{3,20}$`)
)

// isValidURL checks whether a URL is safe to render as a link or image source.
func isSafeURL(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	unescaped := html.UnescapeString(rawURL)
	u, err := url.Parse(unescaped)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
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
	for i := 0; i < 5; i++ {
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

		// Size tags (1-7 or safe pixel/percentage)
		text = reSize.ReplaceAllStringFunc(text, func(m string) string {
			match := reSize.FindStringSubmatch(m)
			if len(match) == 3 {
				sizeVal := match[1]
				content := match[2]
				if n, err := strconv.Atoi(sizeVal); err == nil {
					sizes := map[int]string{
						1: "0.75rem", 2: "0.85rem", 3: "1rem",
						4: "1.15rem", 5: "1.3rem", 6: "1.5rem", 7: "1.85rem",
					}
					if cssSize, ok := sizes[n]; ok {
						return fmt.Sprintf(`<span style="font-size: %s;">%s</span>`, cssSize, content)
					}
				}
				return content
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

	// 4. URLs
	text = reURLParam.ReplaceAllStringFunc(text, func(m string) string {
		match := reURLParam.FindStringSubmatch(m)
		if len(match) == 3 {
			targetURL := strings.TrimSpace(match[1])
			linkText := match[2]
			if isSafeURL(targetURL) {
				return fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, html.EscapeString(targetURL), linkText)
			}
			return linkText
		}
		return m
	})

	text = reURLSimple.ReplaceAllStringFunc(text, func(m string) string {
		match := reURLSimple.FindStringSubmatch(m)
		if len(match) == 2 {
			targetURL := strings.TrimSpace(match[1])
			if isSafeURL(targetURL) {
				return fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, html.EscapeString(targetURL), html.EscapeString(targetURL))
			}
			return html.EscapeString(targetURL)
		}
		return m
	})

	// 5. Images
	text = reImg.ReplaceAllStringFunc(text, func(m string) string {
		match := reImg.FindStringSubmatch(m)
		if len(match) == 2 {
			imgURL := strings.TrimSpace(match[1])
			if isSafeURL(imgURL) {
				return fmt.Sprintf(`<img src="%s" alt="" style="max-width: 100%%; height: auto; border-radius: 4px;" />`, html.EscapeString(imgURL))
			}
		}
		return ""
	})

	// 6. Lists
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

	// 7. Convert newlines to <br>
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
		{"<br><li", "<li"},
		{"</li><br>", "</li>"},
	}
	for _, bc := range blockCleanups {
		text = strings.ReplaceAll(text, bc.from, bc.to)
	}

	// 8. Restore code blocks
	for idx, codeContent := range codeBlocks {
		placeholder := fmt.Sprintf(placeholderPattern, idx)
		text = strings.ReplaceAll(text, "<br>"+placeholder, placeholder)
		text = strings.ReplaceAll(text, placeholder+"<br>", placeholder)

		renderedCode := fmt.Sprintf(`<pre class="bbcode-code"><code>%s</code></pre>`, codeContent)
		text = strings.ReplaceAll(text, placeholder, renderedCode)
	}

	return template.HTML(text)
}
