from parser import parse_html

HTML = """
<html lang="en">
<head>
<title>Example</title>
<meta name="description" content="A short description." />
<link rel="canonical" href="https://example.com/" />
</head>
<body>
<h1>Main</h1>
<a href="/internal">Internal</a>
<a href="https://external.com/">External</a>
<img src="/img.png" />
<script src="/app.js"></script>
<form action="/submit" method="post"></form>
</body>
</html>
"""


def test_parse_basic_counts():
    info = parse_html(HTML, 'https://example.com/')
    assert info.title == 'Example'
    assert info.internal_links == 1
    assert info.external_links == 1
    assert info.h1_count == 1
    assert info.image_count == 1
    assert info.script_count == 1
    assert info.form_count == 1
