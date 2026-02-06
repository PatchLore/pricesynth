from PIL import Image

def crop_screenshot(input_path, output_path):
    img = Image.open(input_path)
    width, height = img.size

    # Crop coordinates (adjust these to remove browser bar and taskbar)
    # Remove top 60px (browser tabs/URL bar) and bottom 40px (taskbar)
    left = 0
    top = 60  # Adjust this number to crop more/less from top
    right = width
    bottom = height - 40  # Adjust this number to crop from bottom

    cropped = img.crop((left, top, right, bottom))
    cropped.save(output_path)
    print(f"Cropped image saved to {output_path}")

# Usage
crop_screenshot("samplereport.png", "samplereport-cropped.png")
