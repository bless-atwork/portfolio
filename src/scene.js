import * as THREE from 'three'

const prefersReduced =
  typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches

export function initScene(canvas) {
  if (!canvas || prefersReduced) return { destroy() {} }

  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
    powerPreference: 'high-performance',
  })
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75))
  renderer.setClearColor(0x000000, 0)

  const scene = new THREE.Scene()
  const camera = new THREE.PerspectiveCamera(48, 1, 0.1, 100)
  camera.position.z = 6

  const count = 160
  const positions = new Float32Array(count * 3)
  const speeds = new Float32Array(count)

  for (let i = 0; i < count; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 14
    positions[i * 3 + 1] = (Math.random() - 0.5) * 10
    positions[i * 3 + 2] = (Math.random() - 0.5) * 6
    speeds[i] = 0.15 + Math.random() * 0.35
  }

  const geometry = new THREE.BufferGeometry()
  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))

  const material = new THREE.PointsMaterial({
    color: 0xdcd3bd,
    size: 0.035,
    transparent: true,
    opacity: 0.55,
    depthWrite: false,
    sizeAttenuation: true,
  })

  const points = new THREE.Points(geometry, material)
  scene.add(points)

  const mouse = { x: 0, y: 0 }
  const target = { x: 0, y: 0 }
  let raf = 0
  let running = true

  function resize() {
    const { clientWidth: w, clientHeight: h } = canvas
    if (!w || !h) return
    renderer.setSize(w, h, false)
    camera.aspect = w / h
    camera.updateProjectionMatrix()
  }

  function onPointerMove(e) {
    target.x = (e.clientX / window.innerWidth - 0.5) * 2
    target.y = (e.clientY / window.innerHeight - 0.5) * 2
  }

  function onVisibility() {
    running = document.visibilityState === 'visible'
    if (running) tick()
  }

  function tick() {
    if (!running) return
    raf = requestAnimationFrame(tick)

    mouse.x += (target.x - mouse.x) * 0.04
    mouse.y += (target.y - mouse.y) * 0.04

    const pos = geometry.attributes.position.array
    const t = performance.now() * 0.00025

    for (let i = 0; i < count; i++) {
      const ix = i * 3
      pos[ix + 1] += Math.sin(t * speeds[i] + i) * 0.0015
      pos[ix] += Math.cos(t * speeds[i] * 0.7 + i) * 0.0008
    }
    geometry.attributes.position.needsUpdate = true

    points.rotation.y = mouse.x * 0.18
    points.rotation.x = -mouse.y * 0.12
    camera.position.x = mouse.x * 0.35
    camera.position.y = -mouse.y * 0.2
    camera.lookAt(0, 0, 0)

    renderer.render(scene, camera)
  }

  resize()
  window.addEventListener('resize', resize)
  window.addEventListener('pointermove', onPointerMove, { passive: true })
  document.addEventListener('visibilitychange', onVisibility)
  tick()

  return {
    destroy() {
      running = false
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', onPointerMove)
      document.removeEventListener('visibilitychange', onVisibility)
      geometry.dispose()
      material.dispose()
      renderer.dispose()
    },
  }
}
