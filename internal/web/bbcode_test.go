package web

import (
	"strings"
	"testing"
)

func TestRenderBBCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		excluded []string
	}{
		{
			name:     "empty input",
			input:    "",
			expected: []string{},
		},
		{
			name:     "plain text with line breaks",
			input:    "Line 1\nLine 2",
			expected: []string{"Line 1<br>Line 2"},
		},
		{
			name:     "basic formatting tags",
			input:    "[b]bold[/b] [i]italic[/i] [u]underline[/u] [s]strike[/s]",
			expected: []string{"<strong>bold</strong>", "<em>italic</em>", "<u>underline</u>", "<s>strike</s>"},
		},
		{
			name:     "nested formatting tags",
			input:    "[b][i]bold and italic[/i][/b]",
			expected: []string{"<strong><em>bold and italic</em></strong>"},
		},
		{
			name:     "code block preserves content literally without parsing BBCode or running HTML",
			input:    "[code]<b>test</b>\n[url]http://example.com[/url][/code]",
			expected: []string{`<pre class="bbcode-code"><code>&lt;b&gt;test&lt;/b&gt;`, `[url]http://example.com[/url]</code></pre>`},
			excluded: []string{"<strong>", "<a href"},
		},
		{
			name:     "valid http and https links",
			input:    "[url]https://example.com[/url] and [url=http://example.org/path?a=1&b=2]Click here[/url]",
			expected: []string{
				`<a href="https://example.com" target="_blank" rel="noopener noreferrer">https://example.com</a>`,
				`<a href="http://example.org/path?a=1&amp;b=2" target="_blank" rel="noopener noreferrer">Click here</a>`,
			},
		},
		{
			name:     "prevent XSS in url tags",
			input:    `[url=javascript:alert(1)]Malicious Link[/url] and [url]javascript:alert(2)[/url]`,
			expected: []string{"Malicious Link"},
			excluded: []string{`href="javascript:`, `<a href="javascript:`},
		},
		{
			name:     "prevent HTML script injection",
			input:    `<script>alert('pwned')</script>[b]safe[/b]`,
			expected: []string{"&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;", "<strong>safe</strong>"},
			excluded: []string{"<script>"},
		},
		{
			name:     "color tag with safe name and hex",
			input:    `[color=red]Red text[/color] [color=#00ff00]Green text[/color]`,
			expected: []string{`<span style="color: red;">Red text</span>`, `<span style="color: #00ff00;">Green text</span>`},
		},
		{
			name:     "color tag with malicious CSS injection blocked",
			input:    `[color=red;background:url('bad')]Sneaky[/color]`,
			expected: []string{"Sneaky"},
			excluded: []string{"style="},
		},
		{
			name:     "size tag",
			input:    `[size=5]Larger text[/size]`,
			expected: []string{`<span style="font-size: 1.3rem;">Larger text</span>`},
		},
		{
			name:     "quote tags with and without author",
			input:    "[quote=Alice]Hello world[/quote]\n[quote]Anonymous quote[/quote]",
			expected: []string{
				`<blockquote class="bbcode-quote"><div class="bbcode-quote-author">Alice:</div>Hello world</blockquote>`,
				`<blockquote class="bbcode-quote">Anonymous quote</blockquote>`,
			},
		},
		{
			name:     "lists with asterisk items",
			input:    "[list]\n[*]Item 1\n[*]Item 2\n[/list]",
			expected: []string{`<ul class="bbcode-list"><li>Item 1</li><li>Item 2</li></ul>`},
		},
		{
			name:     "ordered list",
			input:    "[list=1]\n[*]First\n[*]Second\n[/list]",
			expected: []string{`<ol class="bbcode-list"><li>First</li><li>Second</li></ol>`},
		},
		{
			name:     "image tag with safe and unsafe URLs",
			input:    "[img]https://example.com/logo.png[/img] [img]javascript:alert(1)[/img]",
			expected: []string{`<img src="https://example.com/logo.png" alt=""`},
			excluded: []string{`javascript:`},
		},
		{
			name:     "alignment tags",
			input:    "[center]Centered[/center] [right]Right-aligned[/right]",
			expected: []string{`<div style="text-align: center;">Centered</div>`, `<div style="text-align: right;">Right-aligned</div>`},
		},
		{
			name:  "minecraft uri scheme with quoted url, center, and percentage sizes",
			input: "[center]\n[size=200][b]🎮 JOIN MINECRAFT[/b][/size]\n\n[url=\"minecraft://connect?serverUrl=15.235.199.194&serverPort=19132\"]\n[size=150][b]🟢 JOIN SURVIVAL[/b][/size]\n[/url]\n\n[url=\"minecraft://connect?serverUrl=15.235.199.194&serverPort=19134\"]\n[size=150][b]🔵 JOIN CREATIVE[/b][/size]\n[/url]\n\n[/center]",
			expected: []string{
				`<div style="text-align: center;">`,
				`<span style="font-size: 200%;"><strong>🎮 JOIN MINECRAFT</strong></span>`,
				`<a href="minecraft://connect?serverUrl=15.235.199.194&amp;serverPort=19132" target="_blank" rel="noopener noreferrer"><span style="font-size: 150%;"><strong>🟢 JOIN SURVIVAL</strong></span></a>`,
				`<a href="minecraft://connect?serverUrl=15.235.199.194&amp;serverPort=19134" target="_blank" rel="noopener noreferrer"><span style="font-size: 150%;"><strong>🔵 JOIN CREATIVE</strong></span></a>`,
				`</div>`,
			},
		},
		{
			name:     "steam and ssh custom uri schemes",
			input:    `[url=steam://connect/127.0.0.1:27015]Join CS:GO[/url] and [url="ssh://root@example.com:22"]SSH[/url]`,
			expected: []string{
				`<a href="steam://connect/127.0.0.1:27015" target="_blank" rel="noopener noreferrer">Join CS:GO</a>`,
				`<a href="ssh://root@example.com:22" target="_blank" rel="noopener noreferrer">SSH</a>`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := string(RenderBBCode(tt.input))
			for _, exp := range tt.expected {
				if !strings.Contains(output, exp) {
					t.Errorf("expected output to contain %q, but got:\n%s", exp, output)
				}
			}
			for _, excl := range tt.excluded {
				if strings.Contains(output, excl) {
					t.Errorf("expected output to NOT contain %q, but got:\n%s", excl, output)
				}
			}
		})
	}
}
