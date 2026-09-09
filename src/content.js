export const site = {
  name: 'Blessing Kwenda',
  title: 'Blessing Kwenda — Data Science & Software Engineering',
  tagline: "Let's create data magic for your special project.",
  email: 'blessatwork@gmail.com',
  github: 'https://github.com/bless-atwork',
  role: 'Data science graduate with software engineering foundations, advancing into cybersecurity',
  bio: "I'm Blessing Kwenda. I've completed a Higher Certificate in Information Systems (Software Development) and a BSc Honours in Information Technology: Data Science at Eduvos. I bring the same focus to code that I bring to sport and landscape photography — patient, precise, and curious. Off the screen you'll find me at calm gatherings or lost in a good soundtrack.",
  howIWork:
    'I like clean experiments, readable code, and solutions that hold up when the data gets messy. I am currently building cybersecurity competence through the ISC2 certification pathway.',
  interests: [
    'Sports',
    'Calm events',
    'Coding',
    'Music',
    'Landscape photography',
  ],
  nav: [
    { id: 'about', label: 'About' },
    { id: 'education', label: 'Education' },
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
  education: [
    {
      status: 'completed',
      title: 'Higher Certificate in Information Systems: Software Development',
      institution: 'Eduvos',
      meta: 'SAQA ID 120688 · NQF Level 5',
      blurb:
        'Career-focused qualification with a strong practical foundation in programming, databases, and application development — including program design, software engineering, and technical project work.',
      highlights: [
        'Java / C# / PHP',
        'Python program design',
        'SQL & databases',
        'Database design',
        'Linux',
        'UML & software engineering',
        'Mobile development',
      ],
    },
    {
      status: 'completed',
      title: 'Bachelor of Science Honours in Information Technology: Data Science',
      institution: 'Eduvos',
      meta: 'SAQA ID 120723 · NQF Level 8',
      blurb:
        'Postgraduate specialisation covering analytics, machine learning methods, NLP, forecasting, microservices, and a substantial research project — with emphasis on communicating insights clearly.',
      highlights: [
        'Python & R analytics',
        'Data mining & ETL',
        'NLP with Python',
        'Time-series forecasting',
        'Data visualisation',
        'Microservices & APIs',
        'Research methods',
      ],
    },
    {
      status: 'in-progress',
      title: 'ISC2 Cybersecurity Certifications',
      institution: 'ISC2',
      meta: 'In progress · Vendor-neutral pathway',
      blurb:
        'Building professional cybersecurity competence — defending systems and people, managing risk, and practising with ethical, employer-trusted standards.',
      highlights: [
        'Security foundations',
        'Risk awareness',
        'Secure practices',
        'Professional ethics',
      ],
      url: 'https://www.isc2.org/certifications',
    },
  ],
  skills: [
    {
      category: 'Software Development',
      items: [
        'Java',
        'C#',
        'PHP',
        'Python',
        'Program design',
        'Software engineering & UML',
        'Mobile development',
        'Linux',
      ],
    },
    {
      category: 'Data Science & Analytics',
      items: [
        'Python for data science',
        'R analytics',
        'Data mining & administration',
        'NLP (NLTK)',
        'Time-series & forecasting',
        'Machine learning foundations',
        'Data visualisation & storytelling',
        'Research methods',
      ],
    },
    {
      category: 'Cybersecurity Foundations',
      items: [
        'Security foundations',
        'Risk awareness',
        'Secure practices',
        'Professional ethics',
        'ISC2 pathway (in progress)',
      ],
    },
    {
      category: 'Tools & Platforms',
      items: [
        'SQL / MySQL / SQL Server',
        'Database design & normalisation',
        'RESTful APIs & microservices',
        'SAS Viya (time series)',
        'Microsoft Office',
        'Git & JavaScript',
        'HTML & CSS',
      ],
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
        'A high-end bento-grid personal site showcasing education, skills, and selected work — hosted on Firebase.',
      tags: ['Vite', 'CSS Grid', 'Firebase'],
    },
  ],
}
