# Design System Document: Tactical Intelligence & Digital Forensics

## 1. Overview & Creative North Star: "The Obsidian Lens"
The Creative North Star for this design system is **"The Obsidian Lens."** In the world of digital forensics, clarity is extracted from the void. This system moves away from the "Hollywood Hacker" cliché of neon chaos, opting instead for a high-end, editorial precision that feels like a redacted intelligence briefing. 

We break the "template" look by utilizing **intentional asymmetry**—offsetting data visualizations and using unconventional horizontal scanning patterns. We reject the standard 12-column grid in favor of a **Modular Data-Stream** layout, where information density is high but meticulously organized through tonal depth rather than structural lines.

## 2. Colors & Surface Philosophy
The palette is rooted in the "deep space" of forensics, using high-chroma greens only as functional beacons within a monochromatic obsidian environment.

### The "No-Line" Rule
Standard 1px solid borders are strictly prohibited for sectioning. Boundaries must be defined solely through background color shifts. A `surface-container-low` section sitting on a `background` provides all the definition a professional eye needs.

### Surface Hierarchy & Nesting
Treat the UI as a series of physical layers. We use "Tonal Stacking" to create depth:
- **Level 0 (Base):** `surface-dim` (#0a0e14) – The void.
- **Level 1 (Sections):** `surface-container` (#151a21) – Large layout blocks.
- **Level 2 (Active Components):** `surface-container-high` (#1b2028) – Cards and focus areas.
- **Level 3 (Pop-overs):** `surface-container-highest` (#20262f) – Modals and tooltips.

### The "Glass & Gradient" Rule
To prevent the UI from feeling "flat" or "static," floating elements must utilize **Glassmorphism**. Use semi-transparent `surface-variant` colors with a `backdrop-blur` of 12px–20px. 
**Signature Texture:** Main CTAs should use a subtle linear gradient from `primary` (#8bfb91) to `primary-container` (#47b656) at a 135-degree angle to provide a "lit from within" technical glow.

## 3. Typography: Technical Authority
We pair the geometric precision of **Space Grotesk** with the neutral, utilitarian clarity of **Inter**.

- **Display & Headlines (Space Grotesk):** These are your "headers" in a terminal. They should feel authoritative. Use `display-lg` for dashboard summaries and `headline-sm` for section titles.
- **Body & Data (Inter):** All forensic data, logs, and terminal outputs use Inter. For raw hex codes or file paths, utilize the `label-sm` scale to maintain high density without sacrificing legibility.
- **Hierarchy Tip:** Use `primary` color for `label-md` tags to highlight keywords (e.g., "MALICIOUS", "ENCRYPTED") within a sea of `on-surface-variant` text.

## 4. Elevation & Depth
In this system, light does not come from "above"—it emanates from the data itself.

- **The Layering Principle:** Avoid shadows for static cards. Instead, place a `surface-container-lowest` (#000000) card on a `surface-container-low` (#0f141a) background to create a "recessed" look.
- **Ambient Shadows:** For floating modals, use a shadow with a 40px blur at 6% opacity, using the `primary` color as the shadow tint rather than black. This mimics the glow of a high-end monitor in a dark room.
- **The "Ghost Border" Fallback:** If a container requires a boundary (e.g., a code snippet block), use the `outline-variant` token at **15% opacity**. Never use a 100% opaque border.

## 5. Components & Data Density

### Buttons
- **Primary:** Gradient fill (`primary` to `primary-container`). White-label text (`on-primary-container`). Corner radius: `sm` (0.125rem) for a sharp, tactical feel.
- **Secondary:** `surface-container-highest` fill with a `primary` "Ghost Border" (20% opacity).
- **Tertiary:** No background. Text-only using `primary-dim`.

### Input Fields
- **Terminal Style:** Use `surface-container-lowest` as the field background. The bottom border uses a `primary` glow (2px) only when focused.
- **Error States:** Use `error` (#ff7351) for the text and a 5% `error_container` wash for the background.

### Cards & Data Lists
- **The Divider Rule:** Strictly forbid the use of horizontal divider lines (`<hr>`). Use the Spacing Scale (e.g., `spacing-4`) to create "rivers of space" or toggle the background between `surface-container` and `surface-container-low` for zebra-striping.
- **Forensic Chips:** Use `secondary-container` for neutral metadata and `primary-fixed-dim` for "Verified" or "Clean" states.

### Specialized Components
- **The "Pulse" Indicator:** A 4px circle using `primary` with a 10px radial glow, used to indicate live data ingestion.
- **Hex-Grid Background:** A subtle, non-interactive repeating pattern on the `background` layer using `outline-variant` at 5% opacity.

## 6. Do's and Don'ts

### Do:
- **Embrace Density:** Forensic analysts prefer seeing 50 rows of data at once over 10 rows with "breathing room." Use `body-sm` and `label-sm` aggressively.
- **Tonal Transitions:** Use background color shifts to guide the eye from the navigation (darkest) to the work area (lighter).
- **Subtle Glows:** Use the `primary` color for hover states on interactive icons to mimic a sensor being activated.

### Don't:
- **Don't use Rounded Corners > 0.5rem:** This is a professional tool, not a consumer social app. Keep corners at `sm` or `md`.
- **Don't use Pure White:** Avoid `#ffffff`. The brightest element should be `on-background` (#f1f3fc) to prevent eye strain during long investigation sessions.
- **Don't use Standard Drop Shadows:** They look "floaty" and disconnected. Stick to tonal layering.

## 7. Spacing Scale Implementation
Precision is everything. Use the `0.5` (0.1rem) and `1` (0.2rem) increments for internal component padding (like buttons and chips) to maintain a compact, "tight" aesthetic. Use `8` (1.75rem) and `10` (2.25rem) for major section margins to ensure the "Obsidian Lens" feels organized and not cluttered.