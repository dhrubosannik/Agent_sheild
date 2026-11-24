# Vercel Deployment Guide

Use `vercel.json`.

Configure Firebase public web variables and `VITE_API_BASE_URL`.

The frontend uses HTTPS to reach the Render FastAPI backend and sends Firebase ID tokens as bearer credentials.

Do not route production API traffic to a local hostname.
