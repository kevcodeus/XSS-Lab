from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

# --- HTML Templates ---
# We use a single base template with slots for specific level content
LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Training Lab</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; background: #f4f4f9; }
        .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav { margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #d63384; font-weight: bold; }
        .nav a:hover { text-decoration: underline; }
        .code-block { background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: monospace; }
        .comment-box { background: #fff3cd; border: 1px solid #ffeeba; padding: 15px; margin-top: 20px; border-radius: 5px; }
        .safe-box { background: #d1e7dd; border: 1px solid #badbcc; padding: 15px; margin-top: 20px; border-radius: 5px; }
        input[type="text"] { padding: 8px; width: 70%; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 8px 15px; background: #d63384; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #a61e61; }
        hr { border: 0; border-top: 1px solid #eee; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS (Cross-Site Scripting) Lab</h1>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/easy">Level 1: Easy</a>
            <a href="/medium">Level 2: Medium</a>
            <a href="/hard">Level 3: Hard</a>
        </div>

        <!-- Content Injection Point -->
        {{ content | safe }}
        
    </div>
</body>
</html>
"""

HOME_CONTENT = """
<h3>Welcome to the XSS Lab</h3>
<p>XSS occurs when an application includes untrusted data in a web page without proper validation or escaping.</p>
<ul>
    <li><strong>Goal:</strong> Make a JavaScript alert popup appear: <code>alert(1)</code></li>
    <li><strong>Level 1:</strong> No protections. Direct reflection.</li>
    <li><strong>Level 2:</strong> Weak filter (removes &lt;script&gt; tags).</li>
    <li><strong>Level 3:</strong> Context-aware encoding (Secure).</li>
</ul>
"""

# Template for the levels
LEVEL_FORM = """
<h3>{{ title }}</h3>
<p>{{ description }}</p>

<div class="code-block">
    # Backend Logic <br>
    {{ code_snippet }}
</div>

<hr>

<form method="GET">
    <label>Post a Comment:</label><br>
    <input type="text" name="comment" placeholder="Hello World" value="{{ input_value }}">
    <button type="submit">Post</button>
</form>

{% if result %}
    <div class="{{ box_class }}">
        <strong>Most Recent Comment:</strong><br>
        <!-- VULNERABILITY IS HERE -->
        {{ result }}
    </div>
{% endif %}
"""

@app.route('/')
def index():
    return render_template_string(LAYOUT, content=HOME_CONTENT)

@app.route('/easy')
def level_easy():
    comment = request.args.get('comment', '')
    
    # VULNERABILITY: We explicitly tell Jinja2 that this content is "safe" (trusted).
    # This prevents Jinja from auto-escaping it.
    # Code logic shown to user:
    snippet = """return render_template_string("{{ comment | safe }}")"""
    
    # In the actual render, we pass the 'result' formatted with | safe manually in the string below
    # so the vulnerability actually triggers.
    form_html = LEVEL_FORM.replace("{{ result }}", "{{ result | safe }}")
    
    return render_template_string(LAYOUT, 
                                  content=render_template_string(form_html, 
                                                               title="Level 1: Easy (Reflected XSS)",
                                                               description="Whatever you type is put directly into the HTML. No filters.",
                                                               code_snippet=snippet,
                                                               input_value=html.escape(comment), # Escape input field only to keep value visible
                                                               result=comment,
                                                               box_class="comment-box"))

@app.route('/medium')
def level_medium():
    comment = request.args.get('comment', '')
    
    snippet = """
    # Weak Filter
    sanitized = comment.replace("<script>", "")
    return render_template_string("{{ sanitized | safe }}")
    """
    
    # WEAK FILTER logic
    sanitized_comment = comment.replace("<script>", "")
    
    form_html = LEVEL_FORM.replace("{{ result }}", "{{ result | safe }}")
    
    return render_template_string(LAYOUT, 
                                  content=render_template_string(form_html, 
                                                               title="Level 2: Medium (Filter Evasion)",
                                                               description="The developer removes '<script>' tags. Can you bypass this?",
                                                               code_snippet=snippet,
                                                               input_value=html.escape(comment),
                                                               result=sanitized_comment,
                                                               box_class="comment-box"))

@app.route('/hard')
def level_hard():
    comment = request.args.get('comment', '')
    
    snippet = """
    # Secure: Auto-Escaping
    # Jinja2 converts < to &lt; and > to &gt; automatically.
    return render_template_string("{{ comment }}")
    """
    
    # SECURE logic: We do NOT add | safe.
    # Jinja2 will automatically convert special chars to HTML entities.
    
    return render_template_string(LAYOUT, 
                                  content=render_template_string(LEVEL_FORM, 
                                                               title="Level 3: Hard (Secure)",
                                                               description="This uses standard templating. The browser sees code as text, not instructions.",
                                                               code_snippet=snippet,
                                                               input_value=html.escape(comment),
                                                               result=comment,
                                                               box_class="safe-box"))

if __name__ == '__main__':
    app.run(debug=True, port=5000)