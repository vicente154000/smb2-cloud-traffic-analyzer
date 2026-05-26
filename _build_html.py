#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build documentacion_tfg.html from documentacion_tfg.md.
Converts markdown to HTML with proper tables, minimal style, no mermaid.
"""
import re

def md_to_html(md_text):
    """Convert markdown to HTML with tables, code blocks, lists."""
    lines = md_text.split('\n')
    html_lines = []
    in_code = False
    in_mermaid = False
    in_table = False
    list_stack = []  # tracks ('ul'|'ol', indent_level)
    
    def close_lists(min_indent=0):
        nonlocal list_stack
        while list_stack and list_stack[-1][1] >= min_indent:
            t, _ = list_stack.pop()
            html_lines.append(f'</{t}>')
    
    def process_inline(text):
        """Process inline formatting: bold, code, links."""
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
        text = text.replace('->', '->')
        text = text.replace('>=', '>=')
        return text
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Code blocks
        if line.startswith('```'):
            if in_code:
                # Only emit </pre> if we actually opened a <pre>
                if not in_mermaid:
                    html_lines.append('</pre>')
                in_code = False
                in_mermaid = False
            else:
                in_code = True
                in_mermaid = 'mermaid' in line
                if not in_mermaid:
                    html_lines.append('<pre>')
            i += 1
            continue
        
        if in_code:
            if not in_mermaid:
                escaped = line.replace('&', '&').replace('<', '<').replace('>', '>')
                html_lines.append(escaped)
            i += 1
            continue
        
        # Skip the first H1 line (we already have it in the HTML template)
        if line.strip().startswith('# ') and not line.strip().startswith('## '):
            i += 1
            continue
        
        # Horizontal rule
        if line.strip() == '---':
            close_lists()
            html_lines.append('<hr>')
            i += 1
            continue
        
        # Headers
        if line.startswith('## '):
            close_lists()
            html_lines.append(f'<h2>{line[3:]}</h2>')
            i += 1
            continue
        if line.startswith('### '):
            close_lists()
            html_lines.append(f'<h3>{line[4:]}</h3>')
            i += 1
            continue
        
        # Tables
        if '|' in line and line.strip().startswith('|'):
            close_lists()
            cells = [c.strip() for c in line.split('|')]
            cells = [c for c in cells if c]
            
            if all(re.match(r'^-+\s*$', c) for c in cells):
                i += 1
                continue
            
            if not in_table:
                html_lines.append('<table>')
                html_lines.append('<tr>' + ''.join(f'<th>{process_inline(c)}</th>' for c in cells) + '</tr>')
                in_table = True
            else:
                html_lines.append('<tr>' + ''.join(f'<td>{process_inline(c)}</td>' for c in cells) + '</tr>')
            i += 1
            continue
        else:
            if in_table:
                html_lines.append('</table>')
                in_table = False
        
        # Empty line
        if not line.strip():
            close_lists()
            html_lines.append('')
            i += 1
            continue
        
        # Calculate indent level (number of leading spaces)
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        
        # Unordered list
        if stripped.startswith('- '):
            content = process_inline(stripped[2:])
            if not list_stack or list_stack[-1][0] != 'ul' or list_stack[-1][1] != indent:
                close_lists(indent + 1)
                html_lines.append('<ul>')
                list_stack.append(('ul', indent))
            html_lines.append(f'<li>{content}</li>')
            i += 1
            continue
        
        # Ordered list
        m = re.match(r'^(\d+)\.\s', stripped)
        if m:
            content = process_inline(stripped[m.end():])
            if not list_stack or list_stack[-1][0] != 'ol' or list_stack[-1][1] != indent:
                close_lists(indent + 1)
                html_lines.append('<ol>')
                list_stack.append(('ol', indent))
            html_lines.append(f'<li>{content}</li>')
            i += 1
            continue
        
        # Paragraph
        close_lists()
        content = process_inline(stripped)
        if content:
            html_lines.append(f'<p>{content}</p>')
        i += 1
    
    # Close any remaining tags
    if in_code and not in_mermaid:
        html_lines.append('</pre>')
    if in_table:
        html_lines.append('</table>')
    close_lists()
    
    return '\n'.join(html_lines)

def main():
    with open('plans/documentacion_tfg.md', 'r', encoding='utf-8') as f:
        md_content = f.read()
    
    body = md_to_html(md_content)
    
    html = f'''<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Documentacion del Analizador de Trafico SMB2</title>
<style>
</style>
</head>
<body>

<h1>Documentacion del Analizador de Trafico SMB2</h1>

{body}

</body>
</html>'''
    
    with open('plans/documentacion_tfg.html', 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"Written {len(html)} bytes to plans/documentacion_tfg.html")

if __name__ == '__main__':
    main()
