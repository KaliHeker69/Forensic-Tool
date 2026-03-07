The portal employs a clean, minimalistic UI/UX inspired by modern authentication designs, focusing on clarity, accessibility, and security for cybersecurity professionals. It supports seamless login/logout with responsive layouts suitable for local hosting on WSL Arch Linux using FastAPI backend.

## Design Principles
The interface uses soft gradients, balanced spacing, and visual hierarchy to minimize friction during authentication. Color-blind friendly palettes combine icons, labels, and patterns for threat or status indicators, with keyboard navigation and screen reader compatibility. Auto-logout after inactivity enhances security. [dribbble](https://dribbble.com/shots/26947134-Modern-Authentication-UI-Login-Signup-Password-Reset-Flow)

## Login Page
A centered card layout features prominent email and password fields with secure input masking, a "Forgot Password" link, and a bold primary login button. Subtle animations provide feedback on submission, supporting social SSO options like Google for quick access. Minimalist background ensures focus on the form. [figma](https://www.figma.com/community/file/1415315935713521778/modern-login-screens)

## Dashboard Layout
Post-login, a sidebar navigation includes user profile, key sections, and a visible logout button at the top. The main content area displays customizable widgets for security metrics, with real-time updates via efficient polling. Responsive grid adapts to desktop or mobile views. [aufaitux](https://www.aufaitux.com/blog/cybersecurity-dashboard-ui-ux-design/)

## Server Setup Steps
Update Arch Linux packages with `sudo pacman -Syu` then install Python dependencies: `sudo pacman -S python python-pip python-virtualenv`. Create a virtual environment, activate it, and install FastAPI stack: `pip install fastapi uvicorn[standard] python-jose[cryptography] passlib[bcrypt]`. Run the server with `fastapi run main:app --host 0.0.0.0 --port 8000` for local access via http://localhost:8000. [fastapi.tiangolo](https://fastapi.tiangolo.com/deployment/manually/)

## WSL-Specific Hosting
Ensure WSL Arch is updated and port forwarding is enabled in Windows (default for localhost). Access the portal from Windows browser at http://localhost:8000; use `--reload` flag during development but disable in production. Aligns with your timeline explorer project for efficient local forensics web tools. [perplexity](https://www.perplexity.ai/search/e395c591-1657-444b-8eb0-307ec7762970)