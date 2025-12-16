# Tailwind CSS Setup

This project uses Tailwind CSS with the CLI for production builds.

## Development

To rebuild CSS after template changes:

```bash
npm run build:css
```

To watch for changes and rebuild automatically:

```bash
npm run watch:css
```

## Production

The compiled CSS is located at `backend/app/static/output.css` and is served via FastAPI's StaticFiles.

## Installation

If `node_modules` is not present:

```bash
npm install
npm run build:css
```

## Note

- Do NOT use the Tailwind CDN (`cdn.tailwindcss.com`) in production
- The compiled `output.css` is gitignored - run `npm run build:css` after pulling
- Edit `backend/app/static/input.css` to add custom CSS
- Edit `tailwind.config.js` to customize Tailwind configuration
