"""
Embed samplereport.png into index.html as a base64 data URI.
Run from shadow-pricing folder before deploy. Commit the updated index.html.
No separate PNG file is needed on Vercel.

Usage: python embed_sample_image.py [path/to/samplereport.png]
"""
import base64
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
HTML_PATH = SCRIPT_DIR / "index.html"

def main():
    if len(sys.argv) >= 2:
        img_path = Path(sys.argv[1]).resolve()
    else:
        img_path = SCRIPT_DIR / "samplereport.png"
    if not img_path.exists():
        for alt in (SCRIPT_DIR / "static" / "samplereport.png", SCRIPT_DIR.parent / "samplereport.png"):
            if alt.exists():
                img_path = alt
                break
        else:
            msg = f"ERROR: samplereport.png not found (tried {img_path}, static/, parent)"
            print(msg)
            (SCRIPT_DIR / "embed_done.txt").write_text(msg, encoding="utf-8")
            return 1

    html = HTML_PATH.read_text(encoding="utf-8")
    data = base64.b64encode(img_path.read_bytes()).decode("ascii")
    data_uri = f"data:image/png;base64,{data}"

    # Replace the sample report img src (either /samplereport.png or the placeholder data URI)
    html_new = re.sub(
        r'(<img id="sample-report-img"\s+src=")[^"]*(")',
        rf'\g<1>{data_uri}\g<2>',
        html,
        count=1,
    )
    if html_new == html:
        # Fallback: replace any src pointing to samplereport.png
        html_new = re.sub(
            r'src="[^"]*samplereport\.png[^"]*"',
            f'src="{data_uri}"',
            html,
            count=1,
        )
    if html_new == html:
        msg = "WARNING: No sample report img found in index.html"
        print(msg)
        (SCRIPT_DIR / "embed_done.txt").write_text(msg, encoding="utf-8")
        return 1

    HTML_PATH.write_text(html_new, encoding="utf-8")
    msg = f"Embedded image from {img_path} into index.html. Commit and deploy."
    print(msg)
    (SCRIPT_DIR / "embed_done.txt").write_text(msg, encoding="utf-8")
    return 0

if __name__ == "__main__":
    exit(main())
