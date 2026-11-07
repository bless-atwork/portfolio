import './style.css'
import gsap from 'gsap'
import { site } from './content.js'

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

async function initFirebase() {
  const config = {
    apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
    authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
    projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
    storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
    messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
    appId: import.meta.env.VITE_FIREBASE_APP_ID,
    measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID,
  }

  if (!config.apiKey || !import.meta.env.PROD) return

  try {
    const [{ initializeApp }, { getAnalytics, isSupported }] = await Promise.all([
      import('firebase/app'),
      import('firebase/analytics'),
    ])
    const app = initializeApp(config)
    if (await isSupported()) getAnalytics(app)
  } catch {
    // Analytics is optional — never block the portfolio UI.
  }
}

function element(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text != null) node.textContent = text
  return node
}

const SAFE_EDUCATION_STATUS = new Set(['completed', 'in-progress'])

function safeUrl(value) {
  const url = String(value ?? '').trim()
  if (url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\')) return url
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return ''
  }
  if (parsed.protocol === 'https:' || parsed.protocol === 'http:' || parsed.protocol === 'mailto:') {
    return parsed.href
  }
  return ''
}

function renderSkillCards(groups) {
  const fragment = document.createDocumentFragment()
  for (const group of groups) {
    const card = element('article', 'skill-card')
    card.append(element('h3', '', group.category))
    const list = document.createElement('ul')
    for (const item of group.items) list.append(element('li', '', item))
    card.append(list)
    fragment.append(card)
  }
  return fragment
}

function populateOverlays() {
  const aboutLead = document.getElementById('about-lead')
  const aboutBody = document.getElementById('about-body')
  if (aboutLead) aboutLead.textContent = site.bio
  if (aboutBody) aboutBody.textContent = site.howIWork

  const interestList = document.getElementById('interest-list')
  if (interestList) {
    interestList.replaceChildren(...site.interests.map((item) => element('li', '', item)))
  }

  const educationList = document.getElementById('education-list')
  if (educationList) {
    const cards = site.education.map((item) => {
      const status = SAFE_EDUCATION_STATUS.has(item.status) ? item.status : 'completed'
      const statusLabel = status === 'completed' ? 'Completed' : 'In progress'
      const card = element('article', `edu-card edu-card--${status}`)
      const top = element('div', 'edu-card__top')
      top.append(element('span', 'edu-badge', statusLabel), element('span', 'edu-meta', item.meta))
      card.append(top)

      const heading = document.createElement('h3')
      const href = safeUrl(item.url)
      if (href) {
        const link = element('a', '', item.title)
        link.href = href
        link.target = '_blank'
        link.rel = 'noopener noreferrer'
        heading.append(link)
      } else {
        heading.textContent = item.title
      }
      card.append(heading)
      card.append(element('p', 'edu-institution', item.institution))
      card.append(element('p', 'edu-blurb', item.blurb))
      const highlights = element('ul', 'edu-highlights')
      for (const highlight of item.highlights) highlights.append(element('li', '', highlight))
      card.append(highlights)
      return card
    })
    educationList.replaceChildren(...cards)
  }

  const educationSkills = document.getElementById('education-skills-grid')
  if (educationSkills) {
    educationSkills.replaceChildren(renderSkillCards(site.skills))
  }

  const projects = document.getElementById('projects')
  if (projects) {
    const cards = site.projects.map((project) => {
      const href = safeUrl(project.url)
      const card = href ? element('a', 'project-card') : element('article', 'project-card')
      if (href) {
        card.href = href
        card.target = '_blank'
        card.rel = 'noopener noreferrer'
      }
      const top = element('div', 'project-card__top')
      top.append(element('h3', '', project.title))
      if (href) {
        const arrow = element('span', 'arrow', '↗')
        arrow.setAttribute('aria-hidden', 'true')
        top.append(arrow)
      }
      card.append(top)
      card.append(element('p', '', project.summary))
      const tags = element('div', 'tags')
      for (const tagName of project.tags) tags.append(element('span', '', tagName))
      card.append(tags)
      return card
    })
    projects.replaceChildren(...cards)
  }
}

function initOverlays() {
  const overlays = {
    about: document.getElementById('overlay-about'),
    education: document.getElementById('overlay-education'),
    work: document.getElementById('overlay-work'),
  }

  let active = null

  function open(id) {
    const el = overlays[id]
    if (!el) return
    close(false)
    active = el
    el.hidden = false
    document.body.classList.add('is-locked')
    requestAnimationFrame(() => {
      el.classList.add('is-open')
      if (!reducedMotion) {
        gsap.fromTo(
          el.querySelector('.overlay__inner'),
          { y: 24, opacity: 0 },
          { y: 0, opacity: 1, duration: 0.55, ease: 'power3.out' },
        )
      }
    })
    el.querySelector('[data-close]')?.focus()
  }

  function close(animate = true) {
    if (!active) return
    const el = active
    active = null
    document.body.classList.remove('is-locked')

    const finish = () => {
      el.classList.remove('is-open')
      el.hidden = true
    }

    if (!animate || reducedMotion) {
      finish()
      return
    }

    el.classList.remove('is-open')
    window.setTimeout(finish, 480)
  }

  document.querySelectorAll('[data-open]').forEach((btn) => {
    btn.addEventListener('click', () => open(btn.getAttribute('data-open')))
  })

  document.querySelectorAll('[data-open-tile]').forEach((tile) => {
    tile.addEventListener('click', () => open(tile.getAttribute('data-open-tile')))
    tile.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        open(tile.getAttribute('data-open-tile'))
      }
    })
    tile.setAttribute('role', 'button')
    tile.setAttribute('tabindex', '0')
  })

  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.addEventListener('click', () => close())
  })

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close()
  })

  Object.values(overlays).forEach((overlay) => {
    overlay?.addEventListener('click', (e) => {
      if (e.target === overlay) close()
    })
  })
}

function initEntrance() {
  if (reducedMotion) return

  const tiles = document.querySelectorAll('.tile')
  const lines = document.querySelectorAll('.hero__line')

  gsap.from(tiles, {
    opacity: 0,
    y: 36,
    duration: 1,
    stagger: 0.08,
    ease: 'power3.out',
    clearProps: 'opacity,transform',
  })

  if (lines.length) {
    gsap.from(lines, {
      opacity: 0,
      y: 22,
      duration: 0.9,
      stagger: 0.12,
      delay: 0.2,
      ease: 'power3.out',
      clearProps: 'opacity,transform',
    })
  }
}

populateOverlays()
initOverlays()
initEntrance()
initFirebase()
