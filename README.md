# Stego Tool (Static GitHub Pages)

A small in-browser steganography utility with a deliberately "old" utilitarian UI.

## What it does
- Embeds a file across one or more carrier images using 2 LSBs in RGB bytes (alpha untouched).
- Writes PNG outputs for safety (lossless).
- Extracts from the encoded PNG images back into the original file.
- Optional encryption: AES-GCM with a base64 32-byte key (generated in-app).

## Run locally
Just open `index.html` in a browser.

## Deploy on GitHub Pages
1. Create a repo (e.g., `stego-pages`)
2. Add these files to the repo root:
   - `index.html`
   - `style.css`
   - `app.js`
3. GitHub → Settings → Pages
   - Source: `Deploy from a branch`
   - Branch: `main` (root)
4. Your site will appear at: https://<user>.github.io/<repo>/
