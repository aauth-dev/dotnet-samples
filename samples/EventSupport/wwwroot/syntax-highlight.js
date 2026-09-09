(() => {
    const escapeHtml = value => value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;');

    const tokenize = (text, pattern, classify) => {
        let output = '';
        let offset = 0;
        for (const match of text.matchAll(pattern)) {
            output += escapeHtml(text.slice(offset, match.index));
            output += `<span class="${classify(match[0], match.index + match[0].length)}">${escapeHtml(match[0])}</span>`;
            offset = match.index + match[0].length;
        }
        return output + escapeHtml(text.slice(offset));
    };

    const csharpPattern = /\/\/[^\n]*|\/\*[\s\S]*?\*\/|@?\$?"(?:""|\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|#[A-Za-z]+|\b(?:abstract|as|async|await|base|bool|break|byte|case|catch|char|checked|class|const|continue|decimal|default|delegate|do|double|else|enum|event|explicit|extern|false|finally|fixed|float|for|foreach|goto|if|implicit|in|int|interface|internal|is|lock|long|namespace|new|null|object|operator|out|override|params|private|protected|public|readonly|record|ref|required|return|sbyte|sealed|short|sizeof|stackalloc|static|string|struct|switch|this|throw|true|try|typeof|uint|ulong|unchecked|unsafe|ushort|using|var|virtual|void|volatile|while|with|yield)\b|\b[A-Z][A-Za-z0-9_]*\b|\b\d+(?:\.\d+)?\b/gm;
    const jsonPattern = /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b|\b(?:true|false|null)\b/gi;
    const httpPattern = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|HTTP\/\d(?:\.\d)?)[^\n]*|^[A-Za-z][A-Za-z0-9-]*(?=:)|\b\d{3}\b/gm;

    const highlight = element => {
        if (element.classList.contains('hljs')) return;
        const text = element.textContent ?? '';
        let html;
        if (element.classList.contains('language-json')) {
            html = tokenize(text, jsonPattern, (token, end) => token.startsWith('"')
                ? (text.slice(end).trimStart().startsWith(':') ? 'hljs-attr' : 'hljs-string')
                : /true|false|null/i.test(token) ? 'hljs-literal' : 'hljs-number');
        } else if (element.classList.contains('language-http')) {
            html = tokenize(text, httpPattern, token => /^\d{3}$/.test(token)
                ? 'hljs-number' : token.includes(' ') ? 'hljs-keyword' : 'hljs-attr');
        } else if (element.classList.contains('language-csharp')) {
            html = tokenize(text, csharpPattern, token => token.startsWith('//') || token.startsWith('/*')
                ? 'hljs-comment' : token.includes('"') || token.startsWith("'")
                    ? 'hljs-string' : token.startsWith('#')
                        ? 'hljs-meta' : /^\d/.test(token)
                            ? 'hljs-number' : /^[A-Z]/.test(token)
                                ? 'hljs-title class_' : 'hljs-keyword');
        } else {
            return;
        }
        element.innerHTML = html;
        element.classList.add('hljs');
    };

    window.highlightCode = (root = document) => {
        const scope = root instanceof Element ? root : document;
        if (scope.matches?.('pre code[class*="language-"]')) highlight(scope);
        scope.querySelectorAll('pre code[class*="language-"]:not(.hljs)').forEach(highlight);
    };

    window.highlightCode(document);
    document.addEventListener('enhancedload', () => window.highlightCode(document));
})();
