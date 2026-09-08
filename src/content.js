export const site = {
  name: 'Blessing Kwenda',
  title: 'Blessing Kwenda — Data Science & Software Engineering',
  tagline: "Let's create data magic for your special project.",
  email: 'blessatwork@gmail.com',
  github: 'https://github.com/bless-atwork',
  role: 'Data science student with software engineering skills',
  bio: "I'm Blessing Kwenda, a data science student with software engineering skills. I bring the same focus to code that I bring to sport and landscape photography — patient, precise, and curious. Off the screen you'll find me at calm gatherings or lost in a good soundtrack.",
  howIWork:
    'I like clean experiments, readable code, and solutions that hold up when the data gets messy.',
  interests: [
    'Sports',
    'Calm events',
    'Coding',
    'Music',
    'Landscape photography',
  ],
  nav: [
    { id: 'about', label: 'About' },
    { id: 'work', label: 'Work' },
    { id: 'contact', label: 'Contact', href: 'mailto:blessatwork@gmail.com' },
  ],
  workItems: [
    {
      title: 'Data Science',
      blurb: 'Exploratory analysis, visualization, and insight from raw data.',
    },
    {
      title: 'Software Engineering',
      blurb: 'Building reliable tools and interfaces around data workflows.',
    },
    {
      title: 'Machine Learning',
      blurb: 'Models that turn patterns into practical predictions.',
    },
  ],
  skills: [
    {
      category: 'Data Science',
      items: ['Python', 'Data Analysis', 'Visualization', 'Statistics'],
    },
    {
      category: 'Software Engineering',
      items: ['JavaScript', 'HTML & CSS', 'Git', 'APIs'],
    },
    {
      category: 'Machine Learning',
      items: ['Supervised learning', 'Feature engineering', 'Model evaluation'],
    },
  ],
  projects: [
    {
      title: 'UN Declaration Text Analytics',
      repo: 'data_analytics',
      url: 'https://github.com/bless-atwork/data_analytics',
      summary:
        'Word cloud and frequency analysis of the UN Declaration of Human Rights — stop-word filtering, bar plots, and visual storytelling with Jupyter.',
      tags: ['Python', 'NLP', 'Visualization'],
    },
    {
      title: 'This Portfolio',
      repo: 'portfolio',
      url: 'https://github.com/bless-atwork/portfolio',
      summary:
        'A high-end bento-grid personal site with subtle WebGL particles, 3D tile tilt, and Firebase Hosting.',
      tags: ['Vite', 'Three.js', 'GSAP'],
    },
  ],
}
