# SkillsGuard — Agent Onboarding

Read these files **before doing any work**. They contain the full project context, design system, and aesthetic direction.

## 1. Project Context

Read the project spec first — it defines the product, architecture, tech stack, and scope:

```
HackthonProject.md
```

## 2. Design Skills & System

Read both files in the `.claude/skills/frontend-design/` folder:

- `.claude/skills/frontend-design/SKILL.md` — General frontend design skill (how to approach UI work)
- `.claude/skills/frontend-design/FRONTEND.md` — **Project-specific** design system: color palette, typography, layout patterns, component styles, and tone. This is the source of truth for all visual decisions.

## 3. Reference Site

Quickly scan the saved HTML file for additional context on the visual style we're targeting:

```
Usul - Your AI Platform for Winning Defense Contra.html
```

This is a snapshot of [usul.com](https://usul.com). The file is very large (~2MB, mostly analytics JS). Focus on:
- Lines **674–694** — meta tags, title, description, OG tags
- Lines **1696–2012** — font-face declarations (Chakra Petch, Geist, DM Sans, Fragment Mono, etc.)
- Lines **2084+** — CSS tokens, component styles, SSR markup
- The live site at `https://usul.com` can also be browsed directly for visual reference.

## Summary

**SkillsGuard** is a CLI + web tool that scans GitHub repos for security risks before installation. The landing page should match the aesthetic of usul.com — military-tech confidence, clean SaaS polish, Chakra Petch headings, Geist body text, black/white palette with warm gradient accents, cinematic hero imagery, and product screenshots showing the real UI.
