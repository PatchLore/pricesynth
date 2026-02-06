# Vercel deploy checklist

## Fix: samplereport.png 404 on production

The image must be **committed and pushed** so Vercel includes it in the deployment.

### 1. Confirm the image is tracked

From project root (`shadow-pricing` or `Shadow`, depending on where your git root is):

```bash
git ls-files | grep samplereport
```

- **If you see `samplereport.png`** (or `shadow-pricing/samplereport.png`): the file is tracked. Push your branch and redeploy.
- **If you see nothing**: the file is not in the repo. Continue to step 2.

### 2. Add, commit, and push the image

From the **same directory as your git root** (e.g. `shadow-pricing` if that’s the repo, or `Shadow` if the repo is the parent):

```bash
# If repo root is shadow-pricing:
git add samplereport.png index.html
git commit -m "Add sample report image for landing page"
git push origin main
```

If your repo root is the parent folder (e.g. `Shadow`):

```bash
git add shadow-pricing/samplereport.png shadow-pricing/index.html
git commit -m "Add sample report image for landing page"
git push origin main
```

### 3. Redeploy

```bash
cd shadow-pricing
vercel --prod
```

### 4. Verify

- Open: `https://pricesynth.vercel.app/samplereport.png`  
  You should see the image, not 404.
- Open: `https://pricesynth.vercel.app/`  
  The landing page should show the sample report image.

### HTML change made

`index.html` now uses an absolute path: `src="/samplereport.png?v=1"` so the image is requested from the site root. This works once the file is present in the deployment.
