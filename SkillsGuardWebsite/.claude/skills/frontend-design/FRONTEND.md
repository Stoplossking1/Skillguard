# SkillsGuard Frontend Design System

Reference site: [usul.com](https://usul.com) — a defense-tech SaaS platform built on Framer.

---

## Aesthetic Direction

**Military-tech confidence meets clean modern SaaS.** The design conveys authority, trust, and technical sophistication without feeling cold or bureaucratic. It balances defense industry gravitas with startup polish — cinematic, bold, and purposeful. Every section earns its space. No filler, no decoration without intent.

The overall feel is: a command center distilled into a marketing page. High-information-density when needed (product screenshots, stats), generous whitespace everywhere else.

---

## Color Palette

### Core

| Token              | Value     | Usage                                      |
|--------------------|-----------|---------------------------------------------|
| Black              | `#000`    | Primary text, primary CTA backgrounds, nav  |
| White              | `#fff`    | Page backgrounds, text on dark surfaces      |
| Dark Gray           | `#333` – `#555` | Body copy, secondary text               |
| Light Gray          | `#e5e5e5` – `#f5f5f5` | Borders, dividers, subtle backgrounds |

### Accent Gradients

Warm desert-inspired washes used as section backgrounds — never flat solid fills:

- Peach → Sand (`#f5c6a0` → `#f0dcc0`) — soft, atmospheric
- Light Orange → Warm White (`#f0b87a` → `#faf5ef`) — used behind feature sections
- Cool Blue-Gray (`#c8d8e4`) — appears in hero imagery, subtle steel tones

These gradients are **always muted and diffused**, never saturated. They create atmosphere without competing with content.

### Rules

- Backgrounds are white or warm gradient washes. Never dark-mode by default.
- Black is the dominant accent — used for CTAs, nav bar, announcement banners.
- Avoid saturated brand colors. The palette is intentionally neutral to let product screenshots and imagery carry the color.
- The announcement bar at the top of the page is always solid black with white text.

---

## Typography

### Font Stack

| Role               | Font Family         | Weights         | Usage                                           |
|---------------------|---------------------|-----------------|-------------------------------------------------|
| Display / Headings  | **Chakra Petch**    | 400, 500, 700 (+ italic) | Hero headlines, section titles, large statements |
| Body / UI           | **Geist**           | 400–900 (variable) | Paragraphs, navigation, buttons, labels          |
| Secondary Sans      | **DM Sans**         | 400, 700        | Alternate UI text, smaller headings              |
| Monospace / Data     | **Geist Mono**, **Fragment Mono**, **Space Mono** | 400 | Stats, data labels, technical details, code-like elements |

### Type Rules

- **Hero headlines** use Chakra Petch at very large sizes (60–80px+), often italic, creating an editorial/commanding presence.
- **Section headings** (h2–h3) use Chakra Petch at 32–48px, regular or bold weight.
- **Sub-headings** (h6-level feature titles) use Geist or DM Sans at 20–28px, bold.
- **Body copy** uses Geist at 16–18px, regular weight, with generous line-height (1.5–1.7).
- **Monospace fonts** are reserved for stats, numerical data, product UI labels, and technical metadata.
- Font smoothing is always antialiased (`-webkit-font-smoothing: antialiased`).

---

## Layout & Composition

### Page Structure

```
┌─────────────────────────────────────────────┐
│  Announcement Bar (black, full-width)       │
├─────────────────────────────────────────────┤
│  Navbar (white, logo left, menu right)      │
├─────────────────────────────────────────────┤
│  Hero (full-bleed image, centered text)     │
├─────────────────────────────────────────────┤
│  Social Proof / Logo Bar                    │
├─────────────────────────────────────────────┤
│  Feature Highlight (video or image)         │
├─────────────────────────────────────────────┤
│  Feature Sections (alternating L/R layout)  │
│  ┌──────────┬──────────┐                    │
│  │  Image   │  Text    │                    │
│  └──────────┴──────────┘                    │
│  ┌──────────┬──────────┐                    │
│  │  Text    │  Image   │                    │
│  └──────────┴──────────┘                    │
├─────────────────────────────────────────────┤
│  Quote / Testimonial Block                  │
├─────────────────────────────────────────────┤
│  Stats Section (big numbers)                │
├─────────────────────────────────────────────┤
│  How It Works (stepped process)             │
├─────────────────────────────────────────────┤
│  Method / Workflow Section                  │
├─────────────────────────────────────────────┤
│  Careers / Team CTA                         │
├─────────────────────────────────────────────┤
│  Final CTA (headline + button)              │
├─────────────────────────────────────────────┤
│  Footer (multi-column links + large logo)   │
└─────────────────────────────────────────────┘
```

### Grid & Spacing

- Max content width: **1200px–1440px**, centered.
- Responsive breakpoints: `1440px`, `1200px`, `760px`, `<760px`.
- Section vertical padding: **80–120px** on desktop, **48–64px** on mobile.
- Generous whitespace between sections — let each block breathe.
- Feature sections use a **two-column grid** (roughly 50/50 or 40/60 split) with product screenshots on one side and text on the other, alternating alignment.

### Hero

- **Full-bleed cinematic image** spanning the entire viewport width.
- Text is **centered** over the image with a subtle dark overlay or natural contrast from the image itself.
- Headline is very large (60–80px+), subtitle is 18–20px.
- Two stacked CTAs below the subtitle: a ghost/outline button and a solid black button.

---

## Key Design Patterns

### Announcement Banner
- Solid black, full-width bar pinned to the top of the page.
- White text with an arrow (`→`) linking to a new feature or launch.
- Always concise — one line.

### Navigation
- Clean white background, logo on the left, hamburger menu on the right (mobile-first pattern even on larger viewports for this site).
- Minimal — no mega-menus or dropdown clutter visible on the homepage.

### Buttons

| Type        | Style                                                    | Usage                     |
|-------------|----------------------------------------------------------|---------------------------|
| Primary     | Solid black background, white text, right arrow (`→`)     | Main CTAs ("Book a demo") |
| Secondary   | Transparent with thin white or gray border, dark text     | Supporting CTAs            |
| Text Link   | No background, underline or chevron (`>`), subtle hover   | "Learn more" links         |

- Buttons have slightly rounded corners (4–8px radius), never fully rounded pills.
- Primary buttons include a right-arrow icon for forward momentum.

### Cards & Feature Blocks
- White background with subtle shadow or no border.
- Product screenshots are displayed at slight angles or within browser/app chrome for realism.
- Feature blocks pair a screenshot on one side with a heading + paragraph on the other.

### Stats Section
- Large monospace or bold numbers (e.g., "$1B", "100+", "200%").
- Short descriptor text beneath each stat.
- Arranged in a horizontal row or grid.

### Social Proof
- Logo bar of trusted companies, displayed in grayscale or muted tones.
- Positioned directly below the hero to establish credibility immediately.
- Heading like "Built by and for the most innovative defense companies."

### Quote Block
- Founder or customer quote in large italic or serif-style text.
- Attribution with name, title, and optional photo.
- Centered layout with generous padding.

### Process / Steps
- Numbered steps (Step 1, Step 2, Start Winning) with clear labels.
- Each step has a short heading and 1–2 sentence description.
- Visual progression — vertical or horizontal layout.

### Footer
- Multi-column link layout organized by category (Capture, BD, Solutions, Resources).
- Copyright line with location reference.
- Large watermarked/ghost logo filling the bottom — oversized, faded gray, purely decorative.

---

## Tone & Personality

### Voice
- **Confident and direct.** Statements are declarative, not hedging. "Operate at godspeed." not "We help you work faster."
- **Technical but accessible.** Uses domain-specific language (PEOs, NAICS, recompetes, capture management) but wraps it in clear benefit-driven sentences.
- **Ambitious.** Phrases like "Rethink the future of government contracting" and "Signal through the noise" position the product as a paradigm shift, not an incremental tool.

### Brand Narrative
- The Dune-inspired naming (Usul, Arrakis) creates a **mythic, aspirational identity** — the product is a weapon, a guide, a force multiplier.
- Y Combinator backing is mentioned to signal startup pedigree and velocity.
- "Collaborative AI" is the recurring descriptor — not just automation, but partnership.

### Content Rules
- Headlines are short and punchy (5–8 words max).
- Body copy is concise — 2–3 sentences per feature block.
- Stats are specific and impressive ("$1B in contracts in less than a year").
- CTAs are action-oriented with clear outcomes ("Book a demo", "See Usul in action", "Explore Careers").

---

## Implementation Notes

- Built with **Framer** (React-based, component-driven).
- Uses **Framer Motion** for animations and transitions.
- All fonts loaded via Google Fonts with `font-display: swap`.
- CSS custom properties (tokens) used for theming consistency.
- Responsive design is breakpoint-driven, not fluid — distinct layouts per breakpoint.
- Images served from Framer CDN with optimized formats.
