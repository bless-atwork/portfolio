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

function populateOverlays() {
  const interestList = document.getElementById('interest-list')
  if (interestList) {
    interestList.innerHTML = site.interests
      .map((item) => `<li>${item}</li>`)
      .join('')
  }

  const skillsGrid = document.getElementById('skills-grid')
  if (skillsGrid) {
    skillsGrid.innerHTML = site.skills
      .map(
        (group) => `
      <article class="skill-card">
        <h3>${group.category}</h3>
        <ul>${group.items.map((item) => `<li>${item}</li>`).join('')}</ul>
      </article>`,
      )
      .join('')
  }

  const projects = document.getElementById('projects')
  if (projects) {
    projects.innerHTML = site.projects
      .map(
        (project) => `
      <a class="project-card" href="${project.url}" target="_blank" rel="noopener noreferrer">
        <div class="project-card__top">
          <h3>${project.title}</h3>
          <span class="arrow" aria-hidden="true">↗</span>
        </div>
        <p>${project.summary}</p>
        <div class="tags">${project.tags.map((tag) => `<span>${tag}</span>`).join('')}</div>
      </a>`,
      )
      .join('')
  }
}

function initOverlays() {
  const overlays = {
    about: document.getElementById('overlay-about'),
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
    requestAnimationFrame(() => el.classList.add('is-open'))
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
    window.setTimeout(finish, 420)
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

function initTilt() {
  if (reducedMotion) return

  const max = 6
  const tiles = document.querySelectorAll('[data-tilt]')

  tiles.forEach((tile) => {
    let frame = 0

    tile.addEventListener('pointermove', (e) => {
      const rect = tile.getBoundingClientRect()
      const x = (e.clientX - rect.left) / rect.width
      const y = (e.clientY - rect.top) / rect.height
      const rotateY = (x - 0.5) * max * 2
      const rotateX = (0.5 - y) * max * 2

      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        tile.style.transform = `rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateZ(0)`
      })
    })

    tile.addEventListener('pointerleave', () => {
      cancelAnimationFrame(frame)
      tile.style.transform = 'rotateX(0deg) rotateY(0deg) translateZ(0)'
    })
  })
}

function initEntrance() {
  if (reducedMotion) return

  const tiles = document.querySelectorAll('.tile')
  gsap.from(tiles, {
    opacity: 0,
    y: 28,
    duration: 0.85,
    stagger: 0.07,
    ease: 'power3.out',
    clearProps: 'opacity,transform',
  })
}

async function bootScene() {
  try {
    const { initScene } = await import('./scene.js')
    initScene(document.getElementById('bg-canvas'))
  } catch {
    // WebGL is optional.
  }
}

populateOverlays()
initOverlays()
initTilt()
initEntrance()
bootScene()
initFirebase()
